package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/isovalent/corgi/pkg/github"
	"github.com/isovalent/corgi/pkg/log"
	ops "github.com/isovalent/corgi/pkg/opensearch"
	"github.com/isovalent/corgi/pkg/types"
	"github.com/opensearch-project/opensearch-go"
	"github.com/spf13/cobra"
)

type typeFailureRateParams struct {
	SinceStr   string
	Since      time.Time
	UntilStr   string
	Until      time.Time
	Repository string
	Branch     string
	Events     []string
	Types      []string
	RunsIndex  string
}

func getFailureRate(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	since time.Time,
	until time.Time,
	typ types.TypeName,
	repo *types.Repository,
	runsIndex,
	targetIndex,
	branch,
	event string,
) {
	results := []types.FailureRate{}
	timeSpan := int(until.Sub(since).Hours() / 24.0)

	templateParams, err := ops.NewDocumentCountQueryTemplateParams(
		since, until, typ, branch, repo.Owner.Login, repo.Name, event,
	)
	if err != nil {
		logger.Error("unable to create parameters for document count query", "err", err)
		os.Exit(1)
	}

	l := logger.With("template-params", templateParams, "index", runsIndex)

	failureCounts, err := ops.DoFailureCountRequest(ctx, l, client, runsIndex, templateParams)
	if err != nil {
		l.Error("unable to get failure counts", "err", err)
		os.Exit(1)
	}

	for _, count := range failureCounts {
		f := types.FailureRate{
			Type:               types.TypeNameFailureRate,
			TestType:           string(typ),
			Repository:         *repo,
			Event:              event,
			HeadBranch:         branch,
			Since:              since,
			Until:              until,
			TimeSpanDays:       timeSpan,
			FailureRate:        count.Rate,
			TotalRuns:          count.Total,
			TotalFailures:      count.TotalFailures,
			DocumentIdentifier: count.DocumentIdentifier,
		}

		switch typ {
		case types.TypeNameWorkflowRun:
			f.WorkflowName = count.DocumentIdentifier
		case types.TypeNameJobRun:
			f.JobName = count.DocumentIdentifier
		case types.TypeNameStepRun:
			f.StepName = count.DocumentIdentifier
		default:
			// Callers to this function should ensure that the type
			// name is valid, so if we get here, let's panic.
			panic(fmt.Sprintf("unknown type name: %s", typ))
		}

		results = append(results, f)
	}

	l.Info("Got results from OpenSearch, saving", "num-results", len(results), "target-index", targetIndex)

	if err := ops.BulkWriteObjects[types.FailureRate](results, targetIndex, os.Stdout); err != nil {
		l.Error("Unexpected error while writing failure rate bulk entries", "err", err)
		os.Exit(1)
	}
}

func isSupportedType(typeName types.TypeName) bool {
	switch typeName {
	case types.TypeNameWorkflowRun, types.TypeNameJobRun, types.TypeNameStepRun:
		return true
	default:
		return false
	}
}

var (
	failureRateParams = &typeFailureRateParams{}
	failureRateCmd    = &cobra.Command{
		Use: "failure-rate",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			tz := time.Now().Local().Location()

			since, err := time.ParseInLocation(timeFormatYearMonthDay, failureRateParams.SinceStr, tz)
			if err != nil {
				return fmt.Errorf("unable to parse '%s' in to format of '%s': %w", failureRateParams.SinceStr, timeFormatYearMonthDay, err)
			}

			failureRateParams.Since = since

			until, err := time.ParseInLocation(timeFormatYearMonthDay, failureRateParams.UntilStr, tz)
			if err != nil {
				return fmt.Errorf("unable to parse '%s' in to format of '%s': %w", failureRateParams.UntilStr, timeFormatYearMonthDay, err)
			}

			failureRateParams.Until = until

			for _, typ := range failureRateParams.Types {
				if !isSupportedType(types.TypeName(typ)) {
					return fmt.Errorf("unknown type name: %s", typ)
				}
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			logger := log.NewLogger(rootParams.Verbose)

			repoParts := strings.Split(failureRateParams.Repository, "/")
			if len(repoParts) != 2 {
				logger.Error("Unable to extract repo owner and name from given value", "given", failureRateParams.Repository)
				os.Exit(1)
			}
			repoOwner := repoParts[0]
			repoName := repoParts[1]

			opensearchCfg := ops.NewClientConfig()

			opsClient, err := opensearch.NewClient(opensearchCfg)
			if err != nil {
				logger.Error("Unable to create opensearch client", "err", err)
				os.Exit(1)
			}

			githubClient, err := github.NewGitHubClient(os.Getenv("GITHUB_TOKEN"), logger)
			if err != nil {
				logger.Error("Unable to create GitHub client", "err", err)
				os.Exit(1)
			}

			repo, err := github.GetRepository(ctx, logger, githubClient, repoOwner, repoName)
			if err != nil {
				logger.Error("Unable to query GitHub repository", "err", err)
				os.Exit(1)
			}

			logger.Debug("Got repo", "repo", repo)

			logger.Info("Requesting failure rate counts from OpenSearch", "addresses", opensearchCfg.Addresses)

			for _, event := range failureRateParams.Events {
				for _, typ := range failureRateParams.Types {
					getFailureRate(
						ctx, logger, opsClient,
						failureRateParams.Since, failureRateParams.Until,
						types.TypeName(typ),
						repo, failureRateParams.RunsIndex, rootParams.Index,
						failureRateParams.Branch, event,
					)
				}
			}
		},
	}
)

func init() {
	failureRateCmd.PersistentFlags().StringVarP(
		&failureRateParams.SinceStr, "since", "s", time.Now().Add(-time.Hour*24*7).Format(timeFormatYearMonthDay),
		"Dates specifying how far back in time to query for workflow runs. "+
			"Workflows older than this time will not be counted. "+
			"Uses day granularity. Time is inclusive. Expected format is YYYY-MM-DD.",
	)
	failureRateCmd.PersistentFlags().StringVarP(
		&failureRateParams.UntilStr, "until", "u", time.Now().Format(timeFormatYearMonthDay),
		"Dates specifying the latest point in time to query for workflow runs. "+
			"Workflows created after this time will not be counted. "+
			"Uses day granularity. Time is inclusive. Expected format is YYYY-MM-DD.",
	)
	failureRateCmd.PersistentFlags().StringVarP(
		&failureRateParams.Repository, "repository", "r", "cilium/cilium",
		"Repository to pull workflows from in owner/name format",
	)
	failureRateCmd.PersistentFlags().StringVarP(
		&failureRateParams.Branch, "branch", "b", "main",
		"Name of the branch to pull workflows from",
	)
	failureRateCmd.PersistentFlags().StringSliceVarP(
		&failureRateParams.Events, "events", "e", []string{"push"},
		"Only pull workflows triggered by the given events",
	)
	failureRateCmd.PersistentFlags().StringSliceVarP(
		&failureRateParams.Types, "types", "t", []string{"workflow_run"},
		"The types of runs to pull the failure rates for. Valid values are: "+
			"workflow_run, job_run and step_run",
	)
	failureRateCmd.PersistentFlags().StringVarP(
		&failureRateParams.RunsIndex, "runs-index", "x", "runs-oss",
		"The index to source run information from. This is different than --index, which "+
			"determines the index results will be saved to.",
	)
	rootCmd.AddCommand(failureRateCmd)
}
