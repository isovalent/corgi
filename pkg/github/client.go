package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	ratelimit "github.com/gofri/go-github-ratelimit/github_ratelimit"
	"github.com/google/go-github/v60/github"
	"github.com/hashicorp/go-retryablehttp"
)

func GetGitHubAuthToken() string {
	return os.Getenv("GITHUB_TOKEN")
}

func WrapWithGitHubRetry[T any](
	ctx context.Context,
	logger *slog.Logger,
	target func() (*T, *github.Response, error),
) (*T, *github.Response, error) {
	retries := 0
	for {
		result, response, err := target()
		retryAfter, rateLimitType, rateLimited, rateLimitHeaderErr := githubRateLimitRetry(err, response)
		if rateLimitHeaderErr != nil {
			return result, response, rateLimitHeaderErr
		}
		if rateLimited {
			l := logger.With("err", err, "resp", response, "type", rateLimitType, "sleepTime", retryAfter)
			l.Warn("Hit GitHub rate limit, waiting it out")
			if !waitForRetry(ctx, retryAfter) {
				return nil, response, errors.Join(err, ctx.Err())
			}
			l.Info("GitHub rate limit sleep completed, retrying request")
			continue
		}

		reason := ""
		if response != nil && response.StatusCode >= http.StatusInternalServerError {
			reason = "GitHub server error"
		} else {
			reason = githubRetryReason(ctx, response, err)
		}
		if reason == "" {
			return result, response, err
		}
		if retries >= maxRetryAttempts || ctx.Err() != nil {
			if ctx.Err() != nil {
				return nil, response, errors.Join(err, ctx.Err())
			}
			if err == nil && response != nil && response.StatusCode >= http.StatusInternalServerError {
				err = fmt.Errorf("GitHub returned server error %s", response.Status)
			}
			return result, response, err
		}

		if err == nil && response != nil {
			err = fmt.Errorf("GitHub returned server error %s", response.Status)
		}
		delay := time.Second << retries
		logger.Warn(
			"Retrying GitHub request",
			"reason", reason,
			"error", err,
			"retry", retries+1,
			"max-retries", maxRetryAttempts,
			"sleep-time", delay,
		)
		if response != nil {
			discardHTTPResponse(logger, response.Response)
		}
		if !waitForRetry(ctx, delay) {
			return nil, response, errors.Join(err, ctx.Err())
		}
		retries++
	}
}

const maxRetryAttempts = 5

func githubRetryReason(ctx context.Context, response *github.Response, err error) string {
	if response != nil {
		return ""
	}
	if err == nil {
		return ""
	}
	if isHTTP2PeerCancel(err) {
		return "HTTP/2 peer CANCEL"
	}
	shouldRetry, _ := retryablehttp.ErrorPropagatedRetryPolicy(ctx, nil, err)
	if shouldRetry {
		return "transient transport error"
	}
	return ""
}

func githubRateLimitRetry(err error, response *github.Response) (time.Duration, string, bool, error) {
	if rateLimitErr, ok := err.(*github.AbuseRateLimitError); ok {
		if rateLimitErr.RetryAfter == nil {
			return 0, "", false, nil
		}
		return *rateLimitErr.RetryAfter, "secondary", true, nil
	}
	if _, ok := err.(*github.RateLimitError); ok {
		if response == nil {
			return 0, "", false, nil
		}
		// Give an extra minute for padding.
		return time.Until(response.Rate.Reset.Time) + time.Minute, "primary", true, nil
	}
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		return 0, "", false, nil
	}

	retryAfterHeader := response.Header.Get("X-Ratelimit-Reset")
	if retryAfterHeader == "" {
		return 0, "", false, nil
	}
	retryAfterSec, parseErr := strconv.ParseInt(retryAfterHeader, 10, 64)
	if parseErr != nil {
		return 0, "", false, errors.Join(err, parseErr)
	}
	return time.Until(time.Unix(retryAfterSec, 0)), "primary", true, nil
}

func isHTTP2PeerCancel(err error) bool {
	// The standard library's HTTP/2 stream error type is internal, so identify its peer CANCEL message.
	return err != nil && strings.Contains(err.Error(), "; CANCEL; received from peer")
}

func discardHTTPResponse(logger *slog.Logger, response *http.Response) {
	if response != nil && response.Body != nil {
		if err := response.Body.Close(); err != nil {
			logger.Debug("Failed to close response body before retrying request", "error", err)
		}
	}
}

func waitForRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func NewGitHubClient(authToken string, logger *slog.Logger) (*github.Client, error) {
	// GitHub resets API requests on the top of every hour, so
	// use a two hour delay to handle waiting for the reset.
	// Two hours acts as an extra buffer.
	// We also increase the RetryMax to ensure that the exponential
	// wait gets to the hour long mark.
	// The retry client also has great logic for retrying lots of
	// different types of HTTP errors that are temporary, such as
	// 502 errors.
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 30
	retryClient.RetryWaitMax = 2 * time.Hour
	retryClient.Logger = logger.With("subsys", "github-http-client")

	// This fixes the DownloadArtifact function for the GitHub client.
	// The retryClient will automatically follow redirects, which the GitHub client
	// isn't expecting. The GitHUb client wants to received a 302 Found status code when
	// hitting the download artifact GH API endpoint, using the 'location' header in the
	// response to return the download URL for the artifact. With the retry client, a 200 Ok
	// response is given, so the GitHub client errors out with a weird
	// 'unexpected status code: 200 Ok'.
	// The ErrUseLastReponse error is a special error that signals to the HTTP client to use
	// the last repsonse it recieved, rather than the redirect.
	retryClient.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	rateLimiter, err := ratelimit.NewRateLimitWaiterClient(
		retryClient.StandardClient().Transport,
		ratelimit.WithLimitDetectedCallback(
			func(cc *ratelimit.CallbackContext) {
				logger.Warn(
					"Concurrent rate limit detected, sleeping",
					"sleep-until", cc.SleepUntil, "sleep-duration", cc.TotalSleepTime,
				)
			},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create github rate limiter: %w", err)
	}

	client := github.NewClient(rateLimiter).WithAuthToken(authToken)

	return client, nil
}
