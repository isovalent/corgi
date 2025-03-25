package github

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v60/github"

	"github.com/isovalent/corgi/pkg/junit"
	"github.com/isovalent/corgi/pkg/types"
	"github.com/isovalent/corgi/pkg/util"
)

const PER_PAGE = 100

// GetWorkflowRuns returns a list of workflow runs as determined by the given arguments.
// These workflows can be passed to other functions to retrieve sub-objects, such jobs
// and steps.
func GetWorkflowRuns(
	ctx context.Context,
	logger *slog.Logger,
	client *github.Client,
	repoOwner string,
	repoName string,
	branch string,
	status string,
	event string,
	since time.Time,
	until time.Time,
	workflowID int64,
) ([]*types.WorkflowRun, error) {
	baseLogger := logger.With(
		"repoOwner", repoOwner,
		"repoName", repoName,
		"branch", branch,
		"since", since,
		"until", until,
	)

	workflowRuns := []*types.WorkflowRun{}

	runOpts := github.ListOptions{
		PerPage: PER_PAGE,
	}

	// GH API will return 1000 workflow runs at max. To ensure we don't get cut-off, pull
	// workflows, at most, one day at a time.
	currentTime := until

	for currentTime.Sub(since) >= 0 {
		var dateQuery string

		// Format is based on https://docs.github.com/en/search-github/getting-started-with-searching-on-github/understanding-the-search-syntax#query-for-dates
		// If there is more than 24 hours left in the duration between since and until, then query for
		// a full day.
		// Otherwise, just query for the remaining hours.
		if currentTime.Sub(since) >= time.Hour*24 {
			// GH doesn't have an "equals" date query, so we use the inclusive date range query.
			dateQuery = fmt.Sprintf("%[1]s..%[1]s", currentTime.Format("2006-01-02"))
		} else {
			dateQuery = fmt.Sprintf(
				"%s..%s", since.Format(time.RFC3339), currentTime.Format(time.RFC3339),
			)
		}

		l := baseLogger.With("dateQuery", dateQuery, "page", runOpts.Page)
		l.Info("Pulling workflow runs for repository", "event", event, "status", status, "workflowID", workflowID)

		var (
			runs    *github.WorkflowRuns
			runResp *github.Response
			err     error
		)
		if workflowID != 0 {
			runs, runResp, err = WrapWithRateLimitRetry(
				ctx, l, func() (*github.WorkflowRuns, *github.Response, error) {
					return client.Actions.ListWorkflowRunsByID(
						ctx, repoOwner, repoName, workflowID, &github.ListWorkflowRunsOptions{
							Event:  event,
							Branch: branch,
							// Not relevant. The Pull Requests field in the response
							// returns open PRs that have the same HEAD SHA as the returned
							// workflow run. In other words, the pull_requests field contains
							// pull requests that use the same wversion of the workflow file
							// as the returned workflow run.
							ExcludePullRequests: true,
							Status:              status,
							Created:             dateQuery,
							ListOptions:         runOpts,
						},
					)
				},
			)
		} else {
			runs, runResp, err = WrapWithRateLimitRetry[github.WorkflowRuns](
				ctx, l,
				func() (*github.WorkflowRuns, *github.Response, error) {
					return client.Actions.ListRepositoryWorkflowRuns(
						ctx, repoOwner, repoName, &github.ListWorkflowRunsOptions{
							Event:  event,
							Branch: branch,
							// Not relevant. The Pull Requests field in the response
							// returns open PRs that have the same HEAD SHA as the returned
							// workflow run. In other words, the pull_requests field contains
							// pull requests that use the same wversion of the workflow file
							// as the returned workflow run.
							ExcludePullRequests: true,
							Status:              status,
							Created:             dateQuery,
							ListOptions:         runOpts,
						},
					)
				},
			)
		}

		if err != nil {
			return nil, fmt.Errorf(
				"unable to pull workflow runs for repo %s/%s on branch %s: %w",
				repoOwner, repoName, branch, err,
			)
		}

		l.Info("Processing workflow runs", "total", runs.GetTotalCount(), "count", len(runs.WorkflowRuns))

		for _, runRaw := range runs.WorkflowRuns {
			run := types.NewWorkflowRunFromRaw(runRaw)

			duration, err := GetWorkflowRunDuration(ctx, l, client, run)
			if err != nil {
				return nil, err
			}

			run.WorkflowDuration = duration

			workflowRuns = append(workflowRuns, run)
		}

		if runResp.NextPage == 0 {
			currentTime = currentTime.Add(-time.Hour * 24)
		}

		runOpts.Page = runResp.NextPage
	}

	return workflowRuns, nil
}

// GetWorkflowRunDuration gets the total amount of time that a workflow run took.
// This is retrieved through GitHub's usage API and is not available in a WorkflowRun object itself.
func GetWorkflowRunDuration(
	ctx context.Context,
	logger *slog.Logger,
	client *github.Client,
	run *types.WorkflowRun,
) (time.Duration, error) {
	l := logger.With("workflow-id", run.ID)

	l.Debug("Pulling run duration for workflow")

	usage, _, err := WrapWithRateLimitRetry[github.WorkflowRunUsage](
		ctx, l,
		func() (*github.WorkflowRunUsage, *github.Response, error) {
			return client.Actions.GetWorkflowRunUsageByID(ctx, run.Repository.Owner.Login, run.Repository.Name, run.ID)
		},
	)

	if err != nil {
		return -1, fmt.Errorf(
			"unable to pull workflow run duration for run with ID %d: %w", run.ID, err,
		)
	}

	return time.Duration(usage.GetRunDurationMS() * 1000000), nil
}

// GetTestsForWorkflowRun checks if the given WorkflowRun contains a known JUnit artifact.
// If a JUnit file is found and is recognized, it will be downloaded and parsed into a set of TestSuite
// and Testcase objects.
func GetTestsForWorkflowRun(
	ctx context.Context,
	logger *slog.Logger,
	client *github.Client,
	run *types.WorkflowRun,
	allowedTestConclusions []string,
) ([]types.Testsuite, []types.Testcase, error) {
	l := logger.With("workflow-id", run.ID)

	l.Debug("Pulling artifacts for workflow")

	// Don't expect more than 10 artifacts per workflow run. Cilium
	// runs normally have one to two.
	artifacts, _, err := WrapWithRateLimitRetry[github.ArtifactList](
		ctx, l,
		func() (*github.ArtifactList, *github.Response, error) {
			return client.Actions.ListWorkflowRunArtifacts(
				ctx, run.Repository.Owner.Login, run.Repository.Name, run.ID,
				&github.ListOptions{
					PerPage: 10,
				},
			)
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to list artifacts for workflow %d: %w", run.ID, err)
	}

	l.Debug("Checking artifacts for junit file", "count", artifacts.GetTotalCount())

	var junitArtifact *github.Artifact
	for _, artifact := range artifacts.Artifacts {
		if artifact.GetName() == "cilium-junits" {
			junitArtifact = artifact
		}
	}

	if junitArtifact == nil {
		l.Debug("No junit artifact found for workflow run, ignoring")

		return nil, nil, nil
	}

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("cilium-junits-%d-*", run.ID))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create temp file: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFilePath)
	}()

	l.Info("Junit artifact found for workflow run, downloading", "url", junitArtifact.GetURL())

	downloadURL, downloadURLResp, err := WrapWithRateLimitRetry[url.URL](
		ctx, l,
		func() (*url.URL, *github.Response, error) {
			return client.Actions.DownloadArtifact(
				ctx, run.Repository.Owner.Login, run.Repository.Name,
				junitArtifact.GetID(), 10,
			)
		},
	)
	if err != nil {
		if downloadURLResp.StatusCode == 410 {
			l.Warn("Artiftacts for workflow run are unavailable, received status 410 Gone")

			return nil, nil, nil
		}

		l.Debug("err", "err", err, "status", downloadURLResp.StatusCode, "status-code", downloadURLResp.StatusCode, "equal", downloadURLResp.StatusCode == 200, "body", func() string {
			b := []byte{}
			if _, err := downloadURLResp.Body.Read(b); err != nil {
				return err.Error()
			}
			return string(b)
		}(), "resp", downloadURLResp.Response)

		return nil, nil, fmt.Errorf("unable to get download url for artifact %d: %w", junitArtifact.GetID(), err)
	}

	l.Debug("Downloading cilium-junits artifact", "url", downloadURL, "dest", tmpFilePath)

	resp, err := http.Get(downloadURL.String())
	if err != nil {
		return nil, nil, fmt.Errorf("unable to download cilium-junits artifact from %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf(
			"unable to download cilium-junits artifact from %s, bad http code: %s", downloadURL, resp.Status,
		)
	}

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to write cilium-junits artifact file: %w", err)
	}

	l.Debug("Successfully downloaded cilium-junits file, reading", "path", tmpFilePath)

	zipReader, err := zip.OpenReader(tmpFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create zip reader for file %s: %w", tmpFilePath, err)
	}
	defer zipReader.Close()

	return junit.ParseFiles(zipReader.File, run, allowedTestConclusions, logger)
}

// GetLogsForJob returns a string containing the logs for the given job.
func GetLogsForJob(
	ctx context.Context,
	logger *slog.Logger,
	client *github.Client,
	jobID int64,
	repoOwner string,
	repoName string,
) (string, error) {
	l := logger.With("job-id", jobID)
	l.Info("Pulling logs for job")

	logURL, logURLResp, err := WrapWithRateLimitRetry[url.URL](
		ctx, logger,
		func() (*url.URL, *github.Response, error) {
			return client.Actions.GetWorkflowJobLogs(
				ctx, repoOwner, repoName, jobID, 10,
			)
		},
	)

	if err != nil {
		if logURLResp.StatusCode == 410 {
			l.Warn("Logs for workflow run are unavailable, received status 410 Gone")

			return "", nil
		}

		return "", fmt.Errorf("unable to get log URL for job with ID %d: %w", jobID, err)
	}

	resp, err := http.Get(logURL.String())
	if err != nil {
		return "", fmt.Errorf("unable to download logs for job with ID %d: %w", jobID, err)
	}
	defer resp.Body.Close()

	buf := bytes.Buffer{}
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read logs for job with ID %d: %w", jobID, err)
	}

	return buf.String(), nil
}

func ParseEchoInputsLogs(logs string) map[string]string {
	// The inputs are echoed as a mutli-line JSON object.
	// Example:
	// 2024-05-03T16:34:37.3793382Z Complete job name: Echo Workflow Dispatch Inputs
	// 2024-05-03T16:34:37.4910244Z ##[group]Run echo '{
	// 2024-05-03T16:34:37.4910816Z [36;1mecho '{[0m
	// 2024-05-03T16:34:37.4911353Z [36;1m  "PR-number": "31145",[0m
	// 2024-05-03T16:34:37.4912034Z [36;1m  "SHA": "2d850639650c52d5be3ec7feb1a7e33cd99566c5",[0m
	// 2024-05-03T16:34:37.4912678Z [36;1m  "context-ref": "main",[0m
	// 2024-05-03T16:34:37.4913253Z [36;1m  "extra-args": "{}"[0m
	// 2024-05-03T16:34:37.4913758Z [36;1m}'[0m
	// 2024-05-03T16:34:37.5474074Z shell: /usr/bin/bash -e {0}
	// 2024-05-03T16:34:37.5474692Z env:
	// 2024-05-03T16:34:37.5475032Z   cilium_cli_ci_version:
	// 2024-05-03T16:34:37.5475591Z ##[endgroup]
	// 2024-05-03T16:34:37.5877710Z {
	// 2024-05-03T16:34:37.5878378Z   "PR-number": "31145",
	// 2024-05-03T16:34:37.5879820Z   "SHA": "2d850639650c52d5be3ec7feb1a7e33cd99566c5",
	// 2024-05-03T16:34:37.5880686Z   "context-ref": "main",
	// 2024-05-03T16:34:37.5881137Z   "extra-args": "{}"
	// 2024-05-03T16:34:37.5881540Z }
	// 2024-05-03T16:34:37.6151762Z Cleaning up orphan processes
	inputs := map[string]string{}

	var inGroup bool
	var afterGroup bool

	lines := strings.Split(logs, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		parts := strings.Split(line, " ")

		// Ignore lines we don't care about.
		if !(len(parts) >= 2) {
			continue
		}

		// First part is the timestamp.
		parts = parts[1:]

		if afterGroup {
			if parts[0] == "{" {
				// Beginning of the json object
				continue
			} else if parts[0] == "}" {
				// End of the json object
				break
			}

			// The key value pairs are printed with a three spaces
			// after the timestamp and before the key, therefore strings.Split
			// will add two empty entries in the returned slice:
			// 2024-05-03T16:34:37.5878378Z   "PR-number": "31145",
			parts = parts[2:]

			key := strings.Trim(parts[0], "\":")
			value := strings.Trim(parts[1], "\",")

			inputs[key] = value
		}

		if parts[0] == "##[endgroup]" && inGroup {
			afterGroup = true
			continue
		}

		if len(parts) >= 2 && parts[0] == "##[group]Run" && parts[1] == "echo" {
			inGroup = true
			continue
		}
	}

	return inputs
}

// IsErrorLog returns true if the given log line is deemed as an error log.
func IsErrorLog(line string) bool {
	return strings.Contains(line, "level=error") ||
		strings.Contains(line, "❌") ||
		strings.Contains(line, "🟥") ||
		strings.Contains(line, "ERROR:") ||
		strings.Contains(line, "Warning:") ||
		strings.Contains(line, "Error:") ||
		strings.Contains(line, "[Fail]") ||
		strings.Contains(line, "FAIL!")
}

// GetJobsAndStepsForRun returns a list of jobs and a list of steps that are contained within the given workflow run.
// Jobs and Steps must be parsed together due to the way the GitHub API couples them together.
func GetJobsAndStepsForRun(
	ctx context.Context,
	logger *slog.Logger,
	client *github.Client,
	run *types.WorkflowRun,
	allowedConclusions []string,
	allowedStepConclusions []string,
	includeErrorLogs bool,
) ([]types.JobRun, []types.StepRun, error) {
	l := logger.With("workflow-id", run.ID)

	l.Info("Pulling jobs for workflow run")

	jobOpts := &github.ListOptions{
		PerPage: PER_PAGE,
	}

	jobRuns := []types.JobRun{}
	stepRuns := []types.StepRun{}

	for {
		jobs, jobResp, err := WrapWithRateLimitRetry[github.Jobs](
			ctx, l,
			func() (*github.Jobs, *github.Response, error) {
				return client.Actions.ListWorkflowJobsAttempt(
					ctx,
					run.Repository.Owner.Login,
					run.Repository.Name,
					run.ID,
					int64(run.RunAttempt),
					jobOpts,
				)
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to pull jobs for workflow with ID %d: %w", run.ID, err)
		}

		l.Debug("Processing jobs runs", "total", jobs.GetTotalCount(), "count", len(jobs.Jobs))

		for _, jobRaw := range jobs.Jobs {
			if c := jobRaw.GetConclusion(); !util.Contains(allowedConclusions, c) {
				logger.Debug("Skipping job for workflow, does not meet conclusion criteria",
					"job-id", jobRaw.GetID(),
					"job-conclusion", c,
				)
				continue
			}

			job := types.NewJobRunFromRaw(run, jobRaw)

			if job.Conclusion != "success" && includeErrorLogs {
				logs, err := GetLogsForJob(ctx, logger, client, job.ID, run.Repository.Owner.Login, run.Repository.Name)
				if err != nil {
					return nil, nil, err
				}

				if logs != "" {
					job.ErrorLogs = []string{}

					lines := strings.Split(logs, "\n")
					for _, line := range lines {
						if IsErrorLog(line) {
							job.ErrorLogs = append(job.ErrorLogs, line)
						}
					}
				}
			}

			jobRuns = append(jobRuns, *job)

			steps := GetStepsForJob(ctx, logger, jobRaw, job, allowedStepConclusions)
			stepRuns = append(stepRuns, steps...)
		}

		if jobResp.NextPage == 0 {
			break
		}

		jobOpts.Page = jobResp.NextPage
	}

	return jobRuns, stepRuns, nil
}

func GetStepsForJob(
	ctx context.Context,
	logger *slog.Logger,
	jobRaw *github.WorkflowJob,
	job *types.JobRun,
	allowedConclusions []string,
) []types.StepRun {
	steps := []types.StepRun{}

	for _, stepRaw := range jobRaw.Steps {
		if c := stepRaw.GetConclusion(); !util.Contains(allowedConclusions, c) {
			logger.Debug("Skipping step for job, does not meet conclusion criteria",
				"job-id", jobRaw.GetID(),
				"step-name", stepRaw.GetName(),
				"step-conclusion", c,
			)
			continue
		}

		step := types.NewStepRunFromRaw(job, stepRaw)

		steps = append(steps, *step)
	}

	return steps
}
