package cmd

import (
	"context"

	reportpkg "github.com/isovalent/corgi/pkg/report"
	"github.com/spf13/cobra"
)

var reportCmdParams = reportpkg.DefaultParams()

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate CI failure reports from OpenSearch",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return reportpkg.ValidateParams(&reportCmdParams)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		reportCmdParams.Verbose = rootParams.Verbose
		return reportpkg.Run(context.Background(), &reportCmdParams)
	},
}

func init() {
	reportCmd.PersistentFlags().StringVar(
		&reportCmdParams.OutputDir, "output-dir", reportCmdParams.OutputDir,
		"Directory to write report files to",
	)
	reportCmd.PersistentFlags().StringVar(
		&reportCmdParams.RunsIndex, "runs-index", reportCmdParams.RunsIndex,
		"OpenSearch index to query for run data",
	)
	reportCmd.PersistentFlags().StringSliceVar(
		&reportCmdParams.Repos, "repositories", reportCmdParams.Repos,
		"Repositories to include in reports",
	)
	reportCmd.PersistentFlags().StringSliceVar(
		&reportCmdParams.Events, "events", reportCmdParams.Events,
		"Workflow events to include",
	)
	reportCmd.PersistentFlags().IntVar(
		&reportCmdParams.Top, "top", reportCmdParams.Top,
		"Maximum number of items to include per table",
	)
	reportCmd.PersistentFlags().IntVar(
		&reportCmdParams.MaxLinks, "max-links", reportCmdParams.MaxLinks,
		"Maximum number of links to include per group",
	)

	rootCmd.AddCommand(reportCmd)
}
