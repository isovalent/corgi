package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	gh "github.com/google/go-github/v60/github"
)

func TestWrapWithGitHubRetryRetriesExpectedFailures(t *testing.T) {
	noDelay := time.Duration(0)
	tests := []struct {
		name string
		resp *gh.Response
		err  error
	}{
		{
			name: "server error",
			resp: newGitHubResponse(http.StatusServiceUnavailable),
			err:  errors.New("503 Service Unavailable"),
		},
		{
			name: "not implemented server response",
			resp: newGitHubResponse(http.StatusNotImplemented),
			err:  errors.New("501 Not Implemented"),
		},
		{
			name: "server response without error value",
			resp: newGitHubResponse(http.StatusInternalServerError),
		},
		{
			name: "peer cancelled HTTP/2 stream",
			err:  errors.New("stream error: stream ID 293; CANCEL; received from peer"),
		},
		{
			name: "transient transport error",
			err:  errors.New("connection reset"),
		},
		{
			name: "rate limit",
			resp: newGitHubResponse(http.StatusForbidden),
			err:  &gh.AbuseRateLimitError{RetryAfter: &noDelay},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			want := "ok"
			got, _, err := WrapWithGitHubRetry(
				context.Background(), testLogger(),
				func() (*string, *gh.Response, error) {
					calls++
					if calls == 1 {
						return nil, tt.resp, tt.err
					}
					return &want, newGitHubResponse(http.StatusOK), nil
				},
			)

			if err != nil {
				t.Fatalf("WrapWithGitHubRetry() error = %v", err)
			}
			if calls != 2 {
				t.Fatalf("target called %d times, want 2", calls)
			}
			if got == nil || *got != want {
				t.Fatalf("result = %v, want %q", got, want)
			}
		})
	}
}

func TestWrapWithGitHubRetryDoesNotRetryOtherErrors(t *testing.T) {
	calls := 0
	wantErr := errors.New("bad request")
	_, _, err := WrapWithGitHubRetry(
		context.Background(), testLogger(),
		func() (*string, *gh.Response, error) {
			calls++
			return nil, newGitHubResponse(http.StatusBadRequest), wantErr
		},
	)

	if !errors.Is(err, wantErr) {
		t.Fatalf("WrapWithGitHubRetry() error = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("target called %d times, want 1", calls)
	}
}

func TestWrapWithGitHubRetryRetriesHTTPResponse(t *testing.T) {
	calls := 0
	resp, _, err := WrapWithGitHubRetry[http.Response](
		context.Background(), testLogger(),
		func() (*http.Response, *gh.Response, error) {
			calls++
			status := http.StatusServiceUnavailable
			if calls == 2 {
				status = http.StatusOK
			}
			response := &http.Response{
				StatusCode: status,
				Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
				Body:       io.NopCloser(strings.NewReader("response")),
			}
			return response, &gh.Response{Response: response}, nil
		},
	)

	if err != nil {
		t.Fatalf("WrapWithGitHubRetry() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("target called %d times, want 2", calls)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("response = %v, want HTTP 200", resp)
	}
}

func newGitHubResponse(status int) *gh.Response {
	return &gh.Response{
		Response: &http.Response{
			StatusCode: status,
			Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		},
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
