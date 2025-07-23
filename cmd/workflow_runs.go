package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v60/github"
	"github.com/spf13/cobra"

	gh "github.com/isovalent/corgi/pkg/github"
	"github.com/isovalent/corgi/pkg/log"
	"github.com/isovalent/corgi/pkg/opensearch"
	"github.com/isovalent/corgi/pkg/types"
)

type typeWorkflowRunsParams struct {
	Since                       time.Time
	SinceStr                    string
	Until                       time.Time
	UntilStr                    string
	Repository                  string
	Branch                      string
	Events                      []string
	StepConclusions             []string
	JobConclusions              []string
	TestConclusions             []string
	RunStatuses                 []string
	OnlyFailedSteps             bool
	IncludeTestsuites           bool
	IncludeErrorLogs            bool
	ParseWorkflowDispatchInputs bool
	WorkflowID                  int64
}

func pullRunsWithEventAndStatus(
	ctx context.Context,
	logger *slog.Logger,
	client *github.Client,
	repoOwner,
	repoName,
	event,
	status string,
	workflowID int64,
) {
	eventLogger := logger.With(
		"event", event,
		"status", status,
	)

	runs, err := gh.GetWorkflowRuns(
		ctx, logger, client,
		repoOwner, repoName, workflowRunsParams.Branch,
		status, event, workflowRunsParams.Since, workflowRunsParams.Until,
		workflowID,
	)
	if err != nil {
		eventLogger.Error(
			"Unable to pull workflow runs",
			"err", err,
		)
		if strings.Contains(err.Error(), "404 Not Found") {
			return
		}
		os.Exit(1)
	}

	for _, run := range runs {
		runLogger := eventLogger.With("workflow-id", run.ID)

		jobs, steps, err := gh.GetJobsAndStepsForRun(
			ctx, logger, client, run,
			workflowRunsParams.JobConclusions,
			workflowRunsParams.StepConclusions,
			workflowRunsParams.IncludeErrorLogs,
		)
		if err != nil {
			runLogger.Error(
				"Unable to pull job and steps for workflow run",
				"err", err,
			)
			os.Exit(1)
		}

		// Fields that start with Tested* represent information regarding the tested ref.
		// These fields require special, context-aware handling.
		// TODO: Modify this function to determine if a workflow_dispatch run was scheduled by
		// ariane or executed as part of a PR. Add a flag to ignore PRs.
		//
		// Use 'git log -S setTestedFields' to find a previous implementation of this.
		// setTestedFields(ctx, runLogger, client, event, repoOwner, repoName, run, &jobs)

		if err := opensearch.BulkWriteObjects[types.JobRun](jobs, rootParams.Index, os.Stdout); err != nil {
			runLogger.Error(
				"Unexepected error while writing job run bulk entries",
				"err", err,
			)
			os.Exit(1)
		}

		if err := opensearch.BulkWriteObjects[types.StepRun](steps, rootParams.Index, os.Stdout); err != nil {
			runLogger.Error(
				"Unexepected error while writing step run bulk entries",
				"err", err,
			)
			os.Exit(1)
		}

		suites, cases, err := gh.GetTestsForWorkflowRun(
			ctx, logger, client, run,
			workflowRunsParams.TestConclusions,
		)
		if err != nil {
			runLogger.Error(
				"Unable to parse test cases for workflow run",
				"run", run.ID,
				"err", err,
			)
			os.Exit(1)
		}

		if err := opensearch.BulkWriteObjects[types.Testsuite](suites, rootParams.Index, os.Stdout); err != nil {
			runLogger.Error(
				"Unexepected error while writing job run bulk entries",
				"err", err,
			)
			os.Exit(1)
		}

		if err := opensearch.BulkWriteObjects[types.Testcase](cases, rootParams.Index, os.Stdout); err != nil {
			runLogger.Error(
				"Unexepected error while writing step run bulk entries",
				"err", err,
			)
			os.Exit(1)
		}
	}

	if err := opensearch.BulkWriteObjects[*types.WorkflowRun](runs, rootParams.Index, os.Stdout); err != nil {
		eventLogger.Error(
			"Unexepected error while writing workflow run bulk entries",
			"err", err,
		)
		os.Exit(1)
	}
}

var (
	defaultGitHubConclusions = []string{"success", "failure", "timed_out", "cancelled", "skipped"}
	defaultJUnitConclusions  = []string{"passed", "failed", "skipped"}
	workflowRunsParams       = &typeWorkflowRunsParams{}
	workflowRunsCmd          = &cobra.Command{
		Use: "runs",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			tz := time.Now().Local().Location()

			s, err := time.ParseInLocation(timeFormatYearMonthDayHour, workflowRunsParams.SinceStr, tz)
			if err != nil {
				return fmt.Errorf("unable to parse '%s' to format of '%s': %w", workflowRunsParams.SinceStr, timeFormatYearMonthDayHour, err)
			}

			workflowRunsParams.Since = s

			u, err := time.ParseInLocation(timeFormatYearMonthDayHour, workflowRunsParams.UntilStr, tz)
			if err != nil {
				return fmt.Errorf("unable to parse '%s' to format of '%s': %w", workflowRunsParams.UntilStr, timeFormatYearMonthDayHour, err)
			}

			workflowRunsParams.Until = u

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			logger := log.NewLogger(rootParams.Verbose)

			repoParts := strings.Split(workflowRunsParams.Repository, "/")
			if len(repoParts) != 2 {
				logger.Error("Unable to extract repo owner and name from given value", "given", workflowRunsParams.Repository)
				os.Exit(1)
			}
			repoOwner := repoParts[0]
			repoName := repoParts[1]

			client, err := gh.NewGitHubClient(gh.GetGitHubAuthToken(), logger)
			if err != nil {
				logger.Error("Unable to create new GitHub Client", "err", err)
				os.Exit(1)
			}

			logger.Info(
				"Will pull workflows for the following parameters",
				"repoOwner", repoOwner,
				"repoName", repoName,
				"events", workflowRunsParams.Events,
				"runStatuses", workflowRunsParams.RunStatuses,
				"workflowID", workflowRunsParams.WorkflowID,
			)

			for _, event := range workflowRunsParams.Events {
				for _, status := range workflowRunsParams.RunStatuses {
					pullRunsWithEventAndStatus(
						ctx, logger, client, repoOwner, repoName, event, status, workflowRunsParams.WorkflowID,
					)
				}
			}

		},
	}
)

func init() {
	workflowRunsCmd.PersistentFlags().StringVarP(
		&workflowRunsParams.SinceStr, "since", "s", time.Now().Add(-time.Hour*24*7).Format(timeFormatYearMonthDayHour),
		"Date specifying how far back in time to query for workflow runs. "+
			"Workflows older than this time will not be returned. "+
			"Uses hour granularity. Time is inclusive. Expected format is YYYY-MM-DDTHH.",
	)
	workflowRunsCmd.PersistentFlags().StringVarP(
		&workflowRunsParams.UntilStr, "until", "u", time.Now().Format(timeFormatYearMonthDayHour),
		"Date specifying the latest point in time to query for workflow runs. "+
			"Workflows created after this time will not be returned. "+
			"Uses hour granularity. Time is inclusive. Expected format is YYYY-MM-DDTHH.",
	)
	workflowRunsCmd.PersistentFlags().StringVarP(
		&workflowRunsParams.Repository, "repository", "r", "cilium/cilium",
		"Repository to pull workflows from in owner/name format",
	)
	workflowRunsCmd.PersistentFlags().StringVarP(
		&workflowRunsParams.Branch, "branch", "b", "",
		"Name of the branch to pull workflows from",
	)
	workflowRunsCmd.PersistentFlags().StringSliceVarP(
		&workflowRunsParams.Events, "events", "e", []string{},
		"Only pull workflows triggered by the given events",
	)
	workflowRunsCmd.PersistentFlags().StringSliceVar(
		&workflowRunsParams.StepConclusions, "step-conclusions", defaultGitHubConclusions,
		"Only export steps with one of the given conclusions",
	)
	workflowRunsCmd.PersistentFlags().StringSliceVar(
		&workflowRunsParams.JobConclusions, "job-conclusions", defaultGitHubConclusions,
		"Only export jobs with one of the given conclusions",
	)
	workflowRunsCmd.PersistentFlags().StringSliceVar(
		&workflowRunsParams.TestConclusions, "test-conclusions", defaultJUnitConclusions,
		"Only export test cases with one of the given conclusions. Valid options are 'passed', 'skipped', 'failed'.",
	)
	workflowRunsCmd.PersistentFlags().StringSliceVar(
		&workflowRunsParams.RunStatuses, "run-statuses", defaultGitHubConclusions,
		"Only export runs with one of the given conclusions or statuses",
	)
	workflowRunsCmd.PersistentFlags().BoolVar(
		&workflowRunsParams.IncludeTestsuites, "test-suites", true,
		"Download, parse and attach JUnit artifacts if available",
	)
	workflowRunsCmd.PersistentFlags().BoolVar(
		&workflowRunsParams.IncludeErrorLogs, "error-logs", true,
		"Download logs for each job and include relevant error-specific logs",
	)
	workflowRunsCmd.PersistentFlags().BoolVar(
		&workflowRunsParams.ParseWorkflowDispatchInputs, "parse-wd-inputs", true,
		"For workflow runs triggered by workflow_dispatch that have a job named echo-inputs"+
			"parse logs to determine the inputs given to the trigger. See cilium/cilium#31424",
	)
	workflowRunsCmd.PersistentFlags().Int64VarP(
		&workflowRunsParams.WorkflowID, "workflow-id", "w", 0,
		"Only pull the specified workflow ID and not all workflow runs",
	)
	workflowCmd.AddCommand(workflowRunsCmd)
}
