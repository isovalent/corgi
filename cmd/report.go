package cmd

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/isovalent/corgi/pkg/log"
	ops "github.com/isovalent/corgi/pkg/opensearch"
	"github.com/opensearch-project/opensearch-go"
	"github.com/opensearch-project/opensearch-go/opensearchapi"
	"github.com/spf13/cobra"
)

type reportParams struct {
	OutputDir  string
	RunsIndex  string
	Repos      []string
	Events     []string
	Top        int
	Days       []int
	MaxLinks   int
	Verbose    bool
	FailStatus []string
	TestStatus []string
}

type reportLink struct {
	Workflow  string
	Job       string
	RunNumber int
	RunID     int64
}

type reportGroup struct {
	Key             string
	TestCaseName    string
	FailureMessage  string
	Count           int
	Workflow        string
	TestCaseOwners  []string
	TestSuiteOwners []string
	Links           []reportLink
}

type workflowCount struct {
	Workflow        string
	Count           int
	TotalRuns       int
	TestSuites      []string
	TestCaseOwners  []string
	TestSuiteOwners []string
	Links           []reportLink
}

type workflowSuiteCount struct {
	Branch          string
	Workflow        string
	TestSuite       string
	Count           int
	TotalRuns       int
	TestCaseOwners  []string
	TestSuiteOwners []string
	Links           []reportLink
}

type workflowSuiteFailureGroup struct {
	Branch          string
	Workflow        string
	TestSuite       string
	TestCaseName    string
	FailureMessage  string
	Count           int
	TotalRuns       int
	TestCaseOwners  []string
	TestSuiteOwners []string
	Links           []reportLink
}

type dayPoint struct {
	Date           time.Time
	TotalRuns      int
	TotalFailures  int
	FailureRate    float64
	SeriesFailures map[string]int
	SeriesTotals   map[string]int
}

type reportWindow struct {
	Since time.Time
	Until time.Time
	Days  int
}

type reportSpec struct {
	Title      string
	Slug       string
	Repository string
	Component  string
}

type reportTemplateData struct {
	Spec          reportSpec
	Generated     string
	ExecutionTime string
	Results       []reportResult
}

type landingLink struct {
	Title string
	File  string
}

type landingTemplateData struct {
	Links []landingLink
}

type branchLink struct {
	Name string
	Path string
}

type reportResult struct {
	Window                        reportWindow
	Graphs                        graphBundle
	WorkflowBars                  []workflowBar
	Trends                        []trendItem
	WorkflowFailures              []workflowCount
	BranchWorkflowSuiteFailures   []workflowSuiteCount
	BranchFailureGroupsByWorkflow []branchResult
	OtherBranchResults            []branchResult
	OtherBranches                 []branchLink
}

type branchWindowResult struct {
	Window reportWindow
	Result branchResult
}

type branchReportTemplateData struct {
	Spec          reportSpec
	Branch        string
	Generated     string
	ExecutionTime string
	Results       []branchWindowResult
}

type branchResult struct {
	Branch                string
	Graphs                graphBundle
	WorkflowBars          []workflowBar
	WorkflowFailures      []workflowCount
	WorkflowSuiteFailures []workflowSuiteFailureGroup
	Trends                []trendItem
}

type workflowBar struct {
	Workflow   string
	TotalRuns  int
	TotalFails int
}

var reportCmdParams = &reportParams{}

//go:embed templates/report/*.tmpl
var reportTemplates embed.FS

var reportTemplate = template.Must(template.New("report.md.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	"templates/report/report.md.tmpl",
))

var landingTemplate = template.Must(template.New("landing.md.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	"templates/report/landing.md.tmpl",
))

var branchTemplate = template.Must(template.New("branch.md.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	"templates/report/branch.md.tmpl",
))

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate CI failure reports from OpenSearch",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if reportCmdParams.OutputDir == "" {
			return errors.New("--output-dir is required")
		}
		if reportCmdParams.Top <= 0 {
			return errors.New("--top must be greater than 0")
		}
		if reportCmdParams.MaxLinks <= 0 {
			return errors.New("--max-links must be greater than 0")
		}
		if reportCmdParams.RunsIndex == "" {
			return errors.New("--runs-index is required")
		}
		if len(reportCmdParams.Repos) == 0 {
			return errors.New("--repositories is required")
		}
		if len(reportCmdParams.Events) == 0 {
			return errors.New("--events is required")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := log.NewLogger(reportCmdParams.Verbose)
		ctx := context.Background()

		opensearchCfg := ops.NewClientConfig()
		client, err := opensearch.NewClient(opensearchCfg)
		if err != nil {
			return fmt.Errorf("unable to create OpenSearch client: %w", err)
		}

		reportSpecs := []reportSpec{
			{
				Title:      "Cilium OSS: CI health report",
				Slug:       "Cilium-OSS-CI-health-report",
				Repository: "cilium/cilium",
				Component:  componentFromRepo("cilium/cilium"),
			},
			{
				Title:      "Tetragon OSS: CI health report",
				Slug:       "Tetragon-OSS-CI-health-report",
				Repository: "cilium/tetragon",
				Component:  componentFromRepo("cilium/tetragon"),
			},
		}

		now := time.Now().Local()
		windows := buildReportWindows(now, reportCmdParams.Days)

		landingLinks := make([]landingLink, 0, len(reportSpecs))

		for _, spec := range reportSpecs {
			if !contains(reportCmdParams.Repos, spec.Repository) {
				logger.Debug("Skipping repository not requested", "repo", spec.Repository)
				continue
			}

			reportStart := time.Now()
			results := make([]reportResult, 0, len(windows))
			branchResults := make(map[string][]branchWindowResult)
			for _, window := range windows {
				windowResult, err := buildReportWindow(ctx, logger, client, reportCmdParams, spec.Repository, window)
				if err != nil {
					return fmt.Errorf("unable to build report for %s: %w", spec.Repository, err)
				}
				results = append(results, windowResult)
				for _, branchResult := range windowResult.OtherBranchResults {
					branchResults[branchResult.Branch] = append(
						branchResults[branchResult.Branch],
						branchWindowResult{Window: window, Result: branchResult},
					)
				}
			}

			landingLinks = append(landingLinks, landingLink{
				Title: spec.Title,
				File:  filepath.ToSlash(spec.Component) + "/",
			})

			if err := renderReportFile(reportCmdParams.OutputDir, spec, results, reportStart); err != nil {
				return err
			}

			for branch, branchWindowResults := range branchResults {
				if err := renderBranchReportFile(reportCmdParams.OutputDir, spec, branch, branchWindowResults, reportStart); err != nil {
					return err
				}
			}
		}

		if err := renderLandingPage(reportCmdParams.OutputDir, landingLinks); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	reportCmd.PersistentFlags().StringVar(
		&reportCmdParams.OutputDir, "output-dir", "",
		"Directory to write report files to",
	)
	reportCmd.PersistentFlags().StringVar(
		&reportCmdParams.RunsIndex, "runs-index", "runs-oss",
		"OpenSearch index to query for run data",
	)
	reportCmd.PersistentFlags().StringSliceVar(
		&reportCmdParams.Repos, "repositories", []string{"cilium/cilium", "cilium/tetragon"},
		"Repositories to include in reports",
	)
	reportCmd.PersistentFlags().StringSliceVar(
		&reportCmdParams.Events, "events", []string{"schedule", "push", "workflow_dispatch"},
		"Workflow events to include",
	)
	reportCmd.PersistentFlags().IntVar(
		&reportCmdParams.Top, "top", 50,
		"Maximum number of items to include per table",
	)
	reportCmd.PersistentFlags().IntVar(
		&reportCmdParams.MaxLinks, "max-links", 5,
		"Maximum number of links to include per group",
	)
	reportCmd.PersistentFlags().BoolVarP(
		&reportCmdParams.Verbose, "verbose", "v", false,
		"Enable debug logging",
	)

	reportCmdParams.Days = []int{7, 14, 30, 60, 90}
	reportCmdParams.FailStatus = []string{"failure"}
	reportCmdParams.TestStatus = []string{"failed", "error"}

	rootCmd.AddCommand(reportCmd)
}

func buildReportWindows(now time.Time, days []int) []reportWindow {
	windows := make([]reportWindow, 0, len(days))
	for _, d := range days {
		since := now.AddDate(0, 0, -d)
		windows = append(windows, reportWindow{Since: since, Until: now, Days: d})
	}
	return windows
}

func buildReportWindow(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) (reportResult, error) {
	workflowFailures, err := queryWorkflowFailures(ctx, logger, client, params, repo, window)
	if err != nil {
		return reportResult{}, err
	}

	workflowRunTotals, err := queryWorkflowRunTotals(ctx, logger, client, params, repo, window)
	if err != nil {
		return reportResult{}, err
	}
	applyWorkflowRunTotals(workflowFailures, workflowRunTotals)

	branchWorkflowSuiteFailures, err := queryBranchWorkflowSuiteFailures(ctx, logger, client, params, repo, window)
	if err != nil {
		return reportResult{}, err
	}
	branchWorkflowRunTotals, err := queryBranchWorkflowRunTotals(ctx, logger, client, params, repo, window)
	if err != nil {
		return reportResult{}, err
	}
	applyBranchWorkflowRunTotalsToSuiteCounts(branchWorkflowSuiteFailures, branchWorkflowRunTotals)

	graphs, err := buildGraphData(ctx, logger, client, params, repo, window)
	if err != nil {
		return reportResult{}, err
	}

	workflowBars, err := queryWorkflowBars(ctx, logger, client, params, repo, window)
	if err != nil {
		return reportResult{}, err
	}

	var trends []trendItem
	if window.Days == 7 {
		trends, err = buildTrends(ctx, logger, client, params, repo, window)
		if err != nil {
			return reportResult{}, err
		}
	}

	branches, err := queryFailureBranches(ctx, logger, client, params, repo, window)
	if err != nil {
		return reportResult{}, err
	}

	mainBranches, otherBranches := filterBranchesByPrefix(branches)
	mainBranchResults := make([]branchResult, 0, len(mainBranches))
	otherBranchResults := make([]branchResult, 0, len(otherBranches))

	for _, branch := range mainBranches {
		result, err := buildBranchResult(ctx, logger, client, params, repo, window, branch, branchWorkflowRunTotals)
		if err != nil {
			return reportResult{}, err
		}
		mainBranchResults = append(mainBranchResults, result)
	}

	for _, branch := range otherBranches {
		result, err := buildBranchResult(ctx, logger, client, params, repo, window, branch, branchWorkflowRunTotals)
		if err != nil {
			return reportResult{}, err
		}
		otherBranchResults = append(otherBranchResults, result)
	}

	return reportResult{
		Window:                        window,
		Graphs:                        graphs,
		WorkflowBars:                  workflowBars,
		Trends:                        trends,
		WorkflowFailures:              workflowFailures,
		BranchWorkflowSuiteFailures:   branchWorkflowSuiteFailures,
		BranchFailureGroupsByWorkflow: mainBranchResults,
		OtherBranchResults:            otherBranchResults,
		OtherBranches:                 buildOtherBranchLinks(componentFromRepo(repo), otherBranches),
	}, nil
}

func buildBranchResult(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
	branchWorkflowRunTotals map[string]int,
) (branchResult, error) {
	branchGraphs, err := buildBranchGraphData(ctx, logger, client, params, repo, window, branch)
	if err != nil {
		return branchResult{}, err
	}
	branchWorkflowBars, err := queryWorkflowBarsForBranch(ctx, logger, client, params, repo, window, branch)
	if err != nil {
		return branchResult{}, err
	}
	branchWorkflowFailures, err := queryWorkflowFailuresForBranch(ctx, logger, client, params, repo, window, branch)
	if err != nil {
		return branchResult{}, err
	}
	applyBranchWorkflowRunTotalsToWorkflowCounts(branchWorkflowFailures, branch, branchWorkflowRunTotals)

	branchWorkflowSuiteFailures, err := queryWorkflowSuiteFailureGroupsForBranch(ctx, logger, client, params, repo, window, branch)
	if err != nil {
		return branchResult{}, err
	}
	applyBranchWorkflowRunTotalsToFailureGroups(branchWorkflowSuiteFailures, branch, branchWorkflowRunTotals)
	var branchTrends []trendItem
	if window.Days == 7 {
		branchTrends, err = buildTrendsForBranch(ctx, logger, client, params, repo, window, branch)
		if err != nil {
			return branchResult{}, err
		}
	}
	return branchResult{
		Branch:                branch,
		Graphs:                branchGraphs,
		WorkflowBars:          branchWorkflowBars,
		WorkflowFailures:      branchWorkflowFailures,
		WorkflowSuiteFailures: branchWorkflowSuiteFailures,
		Trends:                branchTrends,
	}, nil
}

func renderReportFile(outputDir string, spec reportSpec, results []reportResult, start time.Time) error {
	path := reportOutputPath(outputDir, spec.Component)
	reportDir := filepath.Dir(path)
	graphDir := filepath.Join(reportDir, "graphs")

	if err := os.MkdirAll(graphDir, 0o755); err != nil {
		return fmt.Errorf("unable to create report graphs directory: %w", err)
	}

	end := time.Now()
	duration := end.Sub(start)

	var b strings.Builder
	data := reportTemplateData{
		Spec:          spec,
		Generated:     end.Format("2006-01-02 15:04 MST"),
		ExecutionTime: formatDuration(duration),
		Results:       results,
	}
	if err := reportTemplate.Execute(&b, data); err != nil {
		return fmt.Errorf("unable to render report template: %w", err)
	}

	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return fmt.Errorf("unable to create report directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("unable to write report file %s: %w", path, err)
	}

	for _, result := range results {
		if err := writeGraphBundle(graphDir, graphPrefix(spec.Slug, result.Window.Days), result.Graphs); err != nil {
			return err
		}
		if err := writeWorkflowBars(graphDir, graphPrefix(spec.Slug, result.Window.Days), result.WorkflowBars); err != nil {
			return err
		}
		for _, branch := range result.BranchFailureGroupsByWorkflow {
			if err := writeGraphBundle(graphDir, branchGraphPrefix(spec.Slug, result.Window.Days, branch.Branch), branch.Graphs); err != nil {
				return err
			}
			if err := writeWorkflowBars(graphDir, branchGraphPrefix(spec.Slug, result.Window.Days, branch.Branch), branch.WorkflowBars); err != nil {
				return err
			}
		}
	}

	return nil
}

func renderBranchReportFile(outputDir string, spec reportSpec, branch string, results []branchWindowResult, start time.Time) error {
	path := branchReportOutputPath(outputDir, spec.Component, branch)
	reportDir := filepath.Dir(path)
	graphDir := filepath.Join(reportDir, "graphs")

	if err := os.MkdirAll(graphDir, 0o755); err != nil {
		return fmt.Errorf("unable to create branch report graphs directory: %w", err)
	}

	end := time.Now()
	duration := end.Sub(start)

	var b strings.Builder
	data := branchReportTemplateData{
		Spec:          spec,
		Branch:        branch,
		Generated:     end.Format("2006-01-02 15:04 MST"),
		ExecutionTime: formatDuration(duration),
		Results:       results,
	}
	if err := branchTemplate.Execute(&b, data); err != nil {
		return fmt.Errorf("unable to render branch report template: %w", err)
	}

	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return fmt.Errorf("unable to create branch report directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("unable to write branch report file %s: %w", path, err)
	}

	for _, result := range results {
		prefix := branchGraphPrefix(spec.Slug, result.Window.Days, branch)
		if err := writeGraphBundle(graphDir, prefix, result.Result.Graphs); err != nil {
			return err
		}
		if err := writeWorkflowBars(graphDir, prefix, result.Result.WorkflowBars); err != nil {
			return err
		}
	}

	return nil
}

func renderLandingPage(outputDir string, links []landingLink) error {
	path := filepath.Join(outputDir, "README.md")
	var b strings.Builder
	data := landingTemplateData{Links: links}
	if err := landingTemplate.Execute(&b, data); err != nil {
		return fmt.Errorf("unable to render landing template: %w", err)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func formatDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	minutes := seconds / 60
	seconds = seconds % 60
	if minutes < 60 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	hours := minutes / 60
	minutes = minutes % 60
	return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
}

func windowTitle(window reportWindow) string {
	return fmt.Sprintf("Last %d days (%s to %s)",
		window.Days,
		window.Since.Format("2006-01-02"),
		window.Until.Format("2006-01-02"),
	)
}

func windowTag(window reportWindow) string {
	return fmt.Sprintf("last %d days", window.Days)
}

func addOne(value int) int {
	return value + 1
}

func reportTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"windowTitle":       windowTitle,
		"windowTag":         windowTag,
		"graphPrefix":       graphPrefix,
		"branchGraphPrefix": branchGraphPrefix,
		"escapePipes":       escapePipes,
		"renderLinks":       renderLinks,
		"join":              strings.Join,
		"add1":              addOne,
		"formatFailureRate": formatFailureRate,
		"formatFailureStat": formatFailureStat,
	}
}

func formatFailureRate(points []dayPoint) string {
	totalRuns := 0
	totalFailures := 0
	for _, point := range points {
		totalRuns += point.TotalRuns
		totalFailures += point.TotalFailures
	}
	percent := 0.0
	if totalRuns > 0 {
		percent = (float64(totalFailures) / float64(totalRuns)) * 100
	}
	return fmt.Sprintf("Failures: %d / %d (%.1f%%)", totalFailures, totalRuns, percent)
}

func formatFailureStat(failures, totalRuns int) string {
	percent := 0.0
	if totalRuns > 0 {
		percent = (float64(failures) / float64(totalRuns)) * 100
	}
	return fmt.Sprintf("%d/%d (%.1f%%)", failures, totalRuns, percent)
}

func queryWorkflowRunTotals(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) (map[string]int, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
				},
			},
		},
		"aggs": map[string]any{
			"workflows": map[string]any{
				"terms": map[string]any{
					"field": "workflow_name.keyword",
					"size":  1000,
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}
	buckets, err := getBuckets(resp, "workflows")
	if err != nil {
		return nil, err
	}

	totals := make(map[string]int, len(buckets))
	for _, bucket := range buckets {
		workflow := getString(bucket, "key")
		if workflow == "" {
			continue
		}
		totals[workflow] = getInt(bucket, "doc_count")
	}

	return totals, nil
}

func queryBranchWorkflowRunTotals(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) (map[string]int, error) {
	totals := map[string]int{}
	var afterKey map[string]any

	for {
		query := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						buildRangeFilter(window.Since, window.Until),
						buildTypeFilter("workflow_run"),
						buildRepoTermFilter(repo),
						buildEventTermsFilter(params.Events),
					},
				},
			},
			"aggs": map[string]any{
				"branch_workflow": map[string]any{
					"composite": map[string]any{
						"size": 1000,
						"sources": []any{
							map[string]any{"branch": map[string]any{"terms": map[string]any{"field": "head_branch.keyword"}}},
							map[string]any{"workflow": map[string]any{"terms": map[string]any{"field": "workflow_name.keyword"}}},
						},
					},
				},
			},
		}

		if afterKey != nil {
			query["aggs"].(map[string]any)["branch_workflow"].(map[string]any)["composite"].(map[string]any)["after"] = afterKey
		}

		addWorkflowExclusions(query)

		resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
		if err != nil {
			return nil, err
		}

		agg, err := getAgg(resp, "branch_workflow")
		if err != nil {
			return nil, err
		}

		buckets, err := getBucketArray(agg)
		if err != nil {
			return nil, err
		}

		for _, bucket := range buckets {
			keyMap := getMap(bucket, "key")
			branch := getStringFromMap(keyMap, "branch")
			workflow := getStringFromMap(keyMap, "workflow")
			if branch == "" || workflow == "" {
				continue
			}
			totals[branchWorkflowRunKey(branch, workflow)] = getInt(bucket, "doc_count")
		}

		afterKey, _ = agg["after_key"].(map[string]any)
		if afterKey == nil {
			break
		}
	}

	return totals, nil
}

func branchWorkflowRunKey(branch, workflow string) string {
	return branch + "::" + workflow
}

func applyWorkflowRunTotals(items []workflowCount, workflowRunTotals map[string]int) {
	for i := range items {
		items[i].TotalRuns = workflowRunTotals[items[i].Workflow]
	}
}

func applyBranchWorkflowRunTotalsToWorkflowCounts(items []workflowCount, branch string, branchWorkflowRunTotals map[string]int) {
	for i := range items {
		items[i].TotalRuns = branchWorkflowRunTotals[branchWorkflowRunKey(branch, items[i].Workflow)]
	}
}

func applyBranchWorkflowRunTotalsToSuiteCounts(items []workflowSuiteCount, branchWorkflowRunTotals map[string]int) {
	for i := range items {
		items[i].TotalRuns = branchWorkflowRunTotals[branchWorkflowRunKey(items[i].Branch, items[i].Workflow)]
	}
}

func applyBranchWorkflowRunTotalsToFailureGroups(items []workflowSuiteFailureGroup, branch string, branchWorkflowRunTotals map[string]int) {
	for i := range items {
		items[i].TotalRuns = branchWorkflowRunTotals[branchWorkflowRunKey(branch, items[i].Workflow)]
	}
}

func queryWorkflowFailures(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) ([]workflowCount, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermsFilter("workflow_conclusion", params.FailStatus),
				},
			},
		},
		"aggs": map[string]any{
			"workflows": map[string]any{
				"terms": map[string]any{
					"field": "workflow_name.keyword",
					"size":  1000,
				},
				"aggs": map[string]any{
					"sample": buildTopHitsAgg(params.MaxLinks),
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}

	buckets, err := getBuckets(resp, "workflows")
	if err != nil {
		return nil, err
	}

	results := make([]workflowCount, 0, len(buckets))
	for _, bucket := range buckets {
		key := getString(bucket, "key")
		count := getInt(bucket, "doc_count")
		links := extractLinksFromBucket(bucket, params.MaxLinks)
		testOwners, suiteOwners := extractOwnersFromBucket(bucket)
		results = append(results, workflowCount{
			Workflow:        key,
			Count:           count,
			TestCaseOwners:  uniqueSorted(testOwners),
			TestSuiteOwners: uniqueSorted(suiteOwners),
			Links:           links,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})
	if len(results) > params.Top {
		results = results[:params.Top]
	}

	for i := range results {
		suites, testOwners, suiteOwners, err := queryWorkflowFailureMeta(
			ctx, logger, client, params, repo, window, results[i].Workflow, "",
		)
		if err != nil {
			return nil, err
		}
		results[i].TestSuites = suites
		results[i].TestCaseOwners = testOwners
		results[i].TestSuiteOwners = suiteOwners
	}

	return results, nil
}

func queryWorkflowFailuresForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
) ([]workflowCount, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermsFilter("workflow_conclusion", params.FailStatus),
					buildTermFilter("head_branch.keyword", branch),
				},
			},
		},
		"aggs": map[string]any{
			"workflows": map[string]any{
				"terms": map[string]any{
					"field": "workflow_name.keyword",
					"size":  1000,
				},
				"aggs": map[string]any{
					"sample": buildTopHitsAgg(params.MaxLinks),
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}

	buckets, err := getBuckets(resp, "workflows")
	if err != nil {
		return nil, err
	}

	results := make([]workflowCount, 0, len(buckets))
	for _, bucket := range buckets {
		key := getString(bucket, "key")
		count := getInt(bucket, "doc_count")
		links := extractLinksFromBucket(bucket, params.MaxLinks)
		testOwners, suiteOwners := extractOwnersFromBucket(bucket)
		results = append(results, workflowCount{
			Workflow:        key,
			Count:           count,
			TestCaseOwners:  uniqueSorted(testOwners),
			TestSuiteOwners: uniqueSorted(suiteOwners),
			Links:           links,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})
	if len(results) > params.Top {
		results = results[:params.Top]
	}

	for i := range results {
		suites, testOwners, suiteOwners, err := queryWorkflowFailureMeta(
			ctx, logger, client, params, repo, window, results[i].Workflow, branch,
		)
		if err != nil {
			return nil, err
		}
		results[i].TestSuites = suites
		results[i].TestCaseOwners = testOwners
		results[i].TestSuiteOwners = suiteOwners
	}

	return results, nil
}

func queryFailureBranches(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) ([]string, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermsFilter("workflow_conclusion", params.FailStatus),
				},
			},
		},
		"aggs": map[string]any{
			"branches": map[string]any{
				"terms": map[string]any{
					"field": "head_branch.keyword",
					"size":  1000,
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}

	buckets, err := getBuckets(resp, "branches")
	if err != nil {
		return nil, err
	}

	results := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		branch := getString(bucket, "key")
		if branch != "" {
			results = append(results, branch)
		}
	}

	sort.Strings(results)
	return results, nil
}

type trendItem struct {
	Workflow string
	Label    string
	Current  int
	Previous int
	Status   string
}

func buildTrends(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) ([]trendItem, error) {
	current, err := queryFailureGroups(ctx, logger, client, params, repo, window)
	if err != nil {
		return nil, err
	}

	prevWindow := reportWindow{
		Since: window.Since.AddDate(0, 0, -window.Days),
		Until: window.Since,
		Days:  window.Days,
	}
	previous, err := queryFailureGroups(ctx, logger, client, params, repo, prevWindow)
	if err != nil {
		return nil, err
	}

	prevMap := map[string]int{}
	for _, item := range previous {
		prevMap[item.Key] = item.Count
	}

	trends := make([]trendItem, 0, len(current))
	for _, item := range current {
		prev := prevMap[item.Key]
		status := "🟠"
		if item.Count < prev {
			status = "🟢"
		} else if item.Count > prev {
			status = "🔴"
		}
		label := fmt.Sprintf("`%s` `%s`", item.TestCaseName, item.FailureMessage)
		trends = append(trends, trendItem{
			Workflow: item.Workflow,
			Label:    label,
			Current:  item.Count,
			Previous: prev,
			Status:   status,
		})
	}

	sort.Slice(trends, func(i, j int) bool {
		return trends[i].Current > trends[j].Current
	})
	if len(trends) > params.Top {
		trends = trends[:params.Top]
	}

	return trends, nil
}

func buildTrendsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
) ([]trendItem, error) {
	current, err := queryFailureGroupsForBranch(ctx, logger, client, params, repo, window, branch)
	if err != nil {
		return nil, err
	}

	prevWindow := reportWindow{
		Since: window.Since.AddDate(0, 0, -window.Days),
		Until: window.Since,
		Days:  window.Days,
	}
	previous, err := queryFailureGroupsForBranch(ctx, logger, client, params, repo, prevWindow, branch)
	if err != nil {
		return nil, err
	}

	prevMap := map[string]int{}
	for _, item := range previous {
		prevMap[item.Key] = item.Count
	}

	trends := make([]trendItem, 0, len(current))
	for _, item := range current {
		prev := prevMap[item.Key]
		status := "🟠"
		if item.Count < prev {
			status = "🟢"
		} else if item.Count > prev {
			status = "🔴"
		}
		label := fmt.Sprintf("`%s` `%s`", item.TestCaseName, item.FailureMessage)
		trends = append(trends, trendItem{
			Workflow: item.Workflow,
			Label:    label,
			Current:  item.Count,
			Previous: prev,
			Status:   status,
		})
	}

	sort.Slice(trends, func(i, j int) bool {
		return trends[i].Current > trends[j].Current
	})
	if len(trends) > params.Top {
		trends = trends[:params.Top]
	}

	return trends, nil
}

func queryWorkflowFailureMeta(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	workflow string,
	branch string,
) ([]string, []string, []string, error) {
	must := []any{
		buildRangeFilter(window.Since, window.Until),
		buildTypeFilter("test_case"),
		buildRepoTermFilter(repo),
		buildEventTermsFilter(params.Events),
		buildTermsFilter("test_case_status", params.TestStatus),
		buildTermFilter("workflow_name.keyword", workflow),
	}
	if branch != "" {
		must = append(must, buildTermFilter("head_branch.keyword", branch))
	}

	return scanFailureOwners(ctx, logger, client, params.RunsIndex, must)
}

func scanFailureOwners(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	index string,
	must []any,
) ([]string, []string, []string, error) {
	suites := map[string]struct{}{}
	testOwners := map[string]struct{}{}
	suiteOwners := map[string]struct{}{}
	var searchAfter []any

	for {
		query := map[string]any{
			"size": 1000,
			"query": map[string]any{
				"bool": map[string]any{
					"must": must,
				},
			},
			"sort": []any{
				map[string]any{"workflow_run_started_at": map[string]any{"order": "asc"}},
				map[string]any{"workflow_id": map[string]any{"order": "asc"}},
			},
			"_source": []string{
				"test_case_owners",
				"test_suite_owners",
				"test_suite_name",
			},
		}

		if len(searchAfter) > 0 {
			query["search_after"] = searchAfter
		}

		addWorkflowExclusions(query)

		resp, err := doSearch(ctx, logger, client, index, query)
		if err != nil {
			return nil, nil, nil, err
		}

		hitsWrapper, ok := resp["hits"].(map[string]any)
		if !ok {
			break
		}
		hitsAny, ok := hitsWrapper["hits"].([]any)
		if !ok || len(hitsAny) == 0 {
			break
		}

		for _, item := range hitsAny {
			hit, ok := item.(map[string]any)
			if !ok {
				continue
			}
			source, ok := hit["_source"].(map[string]any)
			if !ok {
				continue
			}
			if name := getStringFromMap(source, "test_suite_name"); name != "" {
				suites[name] = struct{}{}
			}
			for _, owner := range extractStringSlice(source, "test_case_owners") {
				testOwners[owner] = struct{}{}
			}
			for _, owner := range extractStringSlice(source, "test_suite_owners") {
				suiteOwners[owner] = struct{}{}
			}

			if sortVals, ok := hit["sort"].([]any); ok {
				searchAfter = sortVals
			}
		}

		if len(hitsAny) < 1000 {
			break
		}
	}

	return uniqueSorted(keysFromSet(suites)), uniqueSorted(keysFromSet(testOwners)), uniqueSorted(keysFromSet(suiteOwners)), nil
}

func keysFromSet(input map[string]struct{}) []string {
	result := make([]string, 0, len(input))
	for key := range input {
		result = append(result, key)
	}
	return result
}

func queryBranchWorkflowSuiteFailures(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) ([]workflowSuiteCount, error) {
	var results []workflowSuiteCount
	var afterKey map[string]any

	for {
		query := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						buildRangeFilter(window.Since, window.Until),
						buildTypeFilter("test_case"),
						buildRepoTermFilter(repo),
						buildEventTermsFilter(params.Events),
						buildTermsFilter("test_case_status", params.TestStatus),
					},
				},
			},
			"aggs": map[string]any{
				"branch_workflow_suite": map[string]any{
					"composite": map[string]any{
						"size": 1000,
						"sources": []any{
							map[string]any{"branch": map[string]any{"terms": map[string]any{"field": "head_branch.keyword"}}},
							map[string]any{"workflow": map[string]any{"terms": map[string]any{"field": "workflow_name.keyword"}}},
							map[string]any{"suite": map[string]any{"terms": map[string]any{"field": "test_suite_name.keyword"}}},
						},
					},
					"aggs": map[string]any{
						"sample": buildTopHitsAgg(params.MaxLinks),
					},
				},
			},
		}

		if afterKey != nil {
			query["aggs"].(map[string]any)["branch_workflow_suite"].(map[string]any)["composite"].(map[string]any)["after"] = afterKey
		}

		addWorkflowExclusions(query)

		resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
		if err != nil {
			return nil, err
		}

		agg, err := getAgg(resp, "branch_workflow_suite")
		if err != nil {
			return nil, err
		}

		buckets, err := getBucketArray(agg)
		if err != nil {
			return nil, err
		}

		for _, bucket := range buckets {
			keyMap := getMap(bucket, "key")
			branch := getStringFromMap(keyMap, "branch")
			workflow := getStringFromMap(keyMap, "workflow")
			suite := getStringFromMap(keyMap, "suite")
			count := getInt(bucket, "doc_count")
			links := extractLinksFromBucket(bucket, params.MaxLinks)
			testOwners, suiteOwners := extractOwnersFromBucket(bucket)
			results = append(results, workflowSuiteCount{
				Branch:          branch,
				Workflow:        workflow,
				TestSuite:       suite,
				Count:           count,
				TestCaseOwners:  uniqueSorted(testOwners),
				TestSuiteOwners: uniqueSorted(suiteOwners),
				Links:           links,
			})
		}

		afterKey, _ = agg["after_key"].(map[string]any)
		if afterKey == nil {
			break
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})
	if len(results) > params.Top {
		results = results[:params.Top]
	}

	return results, nil
}

func queryWorkflowSuiteFailureGroupsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
) ([]workflowSuiteFailureGroup, error) {
	groups := map[string]*workflowSuiteFailureGroup{}
	var afterKey map[string]any

	for {
		query := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						buildRangeFilter(window.Since, window.Until),
						buildTypeFilter("test_case"),
						buildRepoTermFilter(repo),
						buildEventTermsFilter(params.Events),
						buildTermsFilter("test_case_status", params.TestStatus),
						buildTermFilter("head_branch.keyword", branch),
					},
				},
			},
			"aggs": map[string]any{
				"workflow_suite_case": map[string]any{
					"composite": map[string]any{
						"size": 1000,
						"sources": []any{
							map[string]any{"workflow": map[string]any{"terms": map[string]any{"field": "workflow_name.keyword"}}},
							map[string]any{"suite": map[string]any{"terms": map[string]any{"field": "test_suite_name.keyword"}}},
							map[string]any{"test_case": map[string]any{"terms": map[string]any{"field": "test_case_name.keyword"}}},
							map[string]any{"message": map[string]any{"terms": map[string]any{"field": "test_case_failure_message.keyword"}}},
						},
					},
					"aggs": map[string]any{
						"sample": buildTopHitsAgg(params.MaxLinks),
					},
				},
			},
		}

		if afterKey != nil {
			query["aggs"].(map[string]any)["workflow_suite_case"].(map[string]any)["composite"].(map[string]any)["after"] = afterKey
		}

		addWorkflowExclusions(query)

		resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
		if err != nil {
			return nil, err
		}

		agg, err := getAgg(resp, "workflow_suite_case")
		if err != nil {
			return nil, err
		}

		buckets, err := getBucketArray(agg)
		if err != nil {
			return nil, err
		}

		for _, bucket := range buckets {
			keyMap := getMap(bucket, "key")
			workflow := getStringFromMap(keyMap, "workflow")
			suite := getStringFromMap(keyMap, "suite")
			testCase := getStringFromMap(keyMap, "test_case")
			message := getStringFromMap(keyMap, "message")
			normalized := normalizeFailureMessage(message)
			count := getInt(bucket, "doc_count")
			links := extractLinksFromBucket(bucket, params.MaxLinks)
			testOwners, suiteOwners := extractOwnersFromBucket(bucket)

			key := fmt.Sprintf("%s::%s::%s::%s", branch, workflow, testCase, normalized)
			group, ok := groups[key]
			if !ok {
				group = &workflowSuiteFailureGroup{
					Branch:         branch,
					Workflow:       workflow,
					TestSuite:      suite,
					TestCaseName:   testCase,
					FailureMessage: normalized,
				}
				groups[key] = group
			}
			group.Count += count
			group.Links = mergeLinks(group.Links, links, params.MaxLinks)
			group.TestCaseOwners = mergeStrings(group.TestCaseOwners, testOwners)
			group.TestSuiteOwners = mergeStrings(group.TestSuiteOwners, suiteOwners)
		}

		afterKey, _ = agg["after_key"].(map[string]any)
		if afterKey == nil {
			break
		}
	}

	results := make([]workflowSuiteFailureGroup, 0, len(groups))
	for _, group := range groups {
		group.TestCaseOwners = uniqueSorted(group.TestCaseOwners)
		group.TestSuiteOwners = uniqueSorted(group.TestSuiteOwners)
		results = append(results, *group)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})
	if len(results) > params.Top {
		results = results[:params.Top]
	}

	return results, nil
}

func queryFailureGroups(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) ([]reportGroup, error) {
	groups := map[string]*reportGroup{}
	var afterKey map[string]any

	for {
		query := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						buildRangeFilter(window.Since, window.Until),
						buildTypeFilter("test_case"),
						buildRepoTermFilter(repo),
						buildEventTermsFilter(params.Events),
						buildTermsFilter("test_case_status", params.TestStatus),
					},
				},
			},
			"aggs": map[string]any{
				"failures": map[string]any{
					"composite": map[string]any{
						"size": 1000,
						"sources": []any{
							map[string]any{"workflow": map[string]any{"terms": map[string]any{"field": "workflow_name.keyword"}}},
							map[string]any{"test_case": map[string]any{"terms": map[string]any{"field": "test_case_name.keyword"}}},
							map[string]any{"message": map[string]any{"terms": map[string]any{"field": "test_case_failure_message.keyword"}}},
						},
					},
					"aggs": map[string]any{
						"sample": buildTopHitsAgg(params.MaxLinks),
					},
				},
			},
		}

		if afterKey != nil {
			query["aggs"].(map[string]any)["failures"].(map[string]any)["composite"].(map[string]any)["after"] = afterKey
		}

		addWorkflowExclusions(query)

		resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
		if err != nil {
			return nil, err
		}

		agg, err := getAgg(resp, "failures")
		if err != nil {
			return nil, err
		}

		buckets, err := getBucketArray(agg)
		if err != nil {
			return nil, err
		}

		for _, bucket := range buckets {
			keyMap := getMap(bucket, "key")
			workflow := getStringFromMap(keyMap, "workflow")
			testCase := getStringFromMap(keyMap, "test_case")
			message := getStringFromMap(keyMap, "message")
			count := getInt(bucket, "doc_count")
			normalized := normalizeFailureMessage(message)
			key := fmt.Sprintf("%s::%s::%s", workflow, testCase, normalized)

			group, ok := groups[key]
			if !ok {
				group = &reportGroup{
					Key:            key,
					TestCaseName:   testCase,
					FailureMessage: normalized,
					Workflow:       workflow,
				}
				groups[key] = group
			}
			group.Count += count

			links, owners, suiteOwners := extractFailureGroupDetails(bucket, params.MaxLinks)
			group.Links = mergeLinks(group.Links, links, params.MaxLinks)
			group.TestCaseOwners = mergeStrings(group.TestCaseOwners, owners)
			group.TestSuiteOwners = mergeStrings(group.TestSuiteOwners, suiteOwners)
		}

		afterKey, _ = agg["after_key"].(map[string]any)
		if afterKey == nil {
			break
		}
	}

	results := make([]reportGroup, 0, len(groups))
	for _, group := range groups {
		group.TestCaseOwners = uniqueSorted(group.TestCaseOwners)
		group.TestSuiteOwners = uniqueSorted(group.TestSuiteOwners)
		results = append(results, *group)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})
	if len(results) > params.Top {
		results = results[:params.Top]
	}

	return results, nil
}

func queryFailureGroupsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
) ([]reportGroup, error) {
	groups := map[string]*reportGroup{}
	var afterKey map[string]any

	for {
		query := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						buildRangeFilter(window.Since, window.Until),
						buildTypeFilter("test_case"),
						buildRepoTermFilter(repo),
						buildEventTermsFilter(params.Events),
						buildTermsFilter("test_case_status", params.TestStatus),
						buildTermFilter("head_branch.keyword", branch),
					},
				},
			},
			"aggs": map[string]any{
				"failures": map[string]any{
					"composite": map[string]any{
						"size": 1000,
						"sources": []any{
							map[string]any{"workflow": map[string]any{"terms": map[string]any{"field": "workflow_name.keyword"}}},
							map[string]any{"test_case": map[string]any{"terms": map[string]any{"field": "test_case_name.keyword"}}},
							map[string]any{"message": map[string]any{"terms": map[string]any{"field": "test_case_failure_message.keyword"}}},
						},
					},
					"aggs": map[string]any{
						"sample": buildTopHitsAgg(params.MaxLinks),
					},
				},
			},
		}

		if afterKey != nil {
			query["aggs"].(map[string]any)["failures"].(map[string]any)["composite"].(map[string]any)["after"] = afterKey
		}

		addWorkflowExclusions(query)

		resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
		if err != nil {
			return nil, err
		}

		agg, err := getAgg(resp, "failures")
		if err != nil {
			return nil, err
		}

		buckets, err := getBucketArray(agg)
		if err != nil {
			return nil, err
		}

		for _, bucket := range buckets {
			keyMap := getMap(bucket, "key")
			workflow := getStringFromMap(keyMap, "workflow")
			testCase := getStringFromMap(keyMap, "test_case")
			message := getStringFromMap(keyMap, "message")
			count := getInt(bucket, "doc_count")
			normalized := normalizeFailureMessage(message)
			key := fmt.Sprintf("%s::%s::%s", workflow, testCase, normalized)

			group, ok := groups[key]
			if !ok {
				group = &reportGroup{
					Key:            key,
					TestCaseName:   testCase,
					FailureMessage: normalized,
					Workflow:       workflow,
				}
				groups[key] = group
			}
			group.Count += count
		}

		afterKey, _ = agg["after_key"].(map[string]any)
		if afterKey == nil {
			break
		}
	}

	results := make([]reportGroup, 0, len(groups))
	for _, group := range groups {
		results = append(results, *group)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})
	if len(results) > params.Top {
		results = results[:params.Top]
	}

	return results, nil
}

// Graphs

type graphBundle struct {
	TotalSeries   []dayPoint
	WorkflowLines []seriesLine
	BranchLines   []seriesLine
}

type seriesLine struct {
	Name   string
	Points []dayPoint
}

type branchWorkflowPair struct {
	Branch   string
	Workflow string
	Count    int
}

func buildGraphData(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) (graphBundle, error) {
	series, err := queryDailyTotals(ctx, logger, client, params, repo, window)
	if err != nil {
		return graphBundle{}, err
	}

	topWorkflows, err := queryTopWorkflows(ctx, logger, client, params, repo, window, 5)
	if err != nil {
		return graphBundle{}, err
	}
	workflowLines := make([]seriesLine, 0, len(topWorkflows))
	for _, wf := range topWorkflows {
		points, err := queryDailyByWorkflow(ctx, logger, client, params, repo, window, wf)
		if err != nil {
			return graphBundle{}, err
		}
		workflowLines = append(workflowLines, seriesLine{Name: wf, Points: points})
	}

	topBranches, err := queryTopBranchWorkflows(ctx, logger, client, params, repo, window, 5)
	if err != nil {
		return graphBundle{}, err
	}
	branchLines := make([]seriesLine, 0, len(topBranches))
	for _, pair := range topBranches {
		points, err := queryDailyByBranchWorkflow(ctx, logger, client, params, repo, window, pair.Branch, pair.Workflow)
		if err != nil {
			return graphBundle{}, err
		}
		branchLines = append(branchLines, seriesLine{Name: fmt.Sprintf("%s/%s", pair.Branch, pair.Workflow), Points: points})
	}

	return graphBundle{TotalSeries: series, WorkflowLines: workflowLines, BranchLines: branchLines}, nil
}

func queryWorkflowBars(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) ([]workflowBar, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
				},
			},
		},
		"aggs": map[string]any{
			"workflows": map[string]any{
				"terms": map[string]any{
					"field": "workflow_name.keyword",
					"size":  params.Top,
				},
				"aggs": map[string]any{
					"failures": map[string]any{
						"filter": map[string]any{
							"terms": map[string]any{"workflow_conclusion": params.FailStatus},
						},
					},
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}
	buckets, err := getBuckets(resp, "workflows")
	if err != nil {
		return nil, err
	}

	results := make([]workflowBar, 0, len(buckets))
	for _, bucket := range buckets {
		workflow := getString(bucket, "key")
		total := getInt(bucket, "doc_count")
		failures := 0
		if failAgg, ok := bucket["failures"].(map[string]any); ok {
			failures = getInt(failAgg, "doc_count")
		}
		results = append(results, workflowBar{Workflow: workflow, TotalRuns: total, TotalFails: failures})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].TotalRuns == results[j].TotalRuns {
			return results[i].TotalFails > results[j].TotalFails
		}
		return results[i].TotalRuns > results[j].TotalRuns
	})

	return results, nil
}

func queryWorkflowBarsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
) ([]workflowBar, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermFilter("head_branch.keyword", branch),
				},
			},
		},
		"aggs": map[string]any{
			"workflows": map[string]any{
				"terms": map[string]any{
					"field": "workflow_name.keyword",
					"size":  params.Top,
				},
				"aggs": map[string]any{
					"failures": map[string]any{
						"filter": map[string]any{
							"terms": map[string]any{"workflow_conclusion": params.FailStatus},
						},
					},
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}
	buckets, err := getBuckets(resp, "workflows")
	if err != nil {
		return nil, err
	}

	results := make([]workflowBar, 0, len(buckets))
	for _, bucket := range buckets {
		workflow := getString(bucket, "key")
		total := getInt(bucket, "doc_count")
		failures := 0
		if failAgg, ok := bucket["failures"].(map[string]any); ok {
			failures = getInt(failAgg, "doc_count")
		}
		results = append(results, workflowBar{Workflow: workflow, TotalRuns: total, TotalFails: failures})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].TotalRuns == results[j].TotalRuns {
			return results[i].TotalFails > results[j].TotalFails
		}
		return results[i].TotalRuns > results[j].TotalRuns
	})

	return results, nil
}

func buildBranchGraphData(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
) (graphBundle, error) {
	series, err := queryDailyTotalsForBranch(ctx, logger, client, params, repo, window, branch)
	if err != nil {
		return graphBundle{}, err
	}

	topWorkflows, err := queryTopWorkflowsForBranch(ctx, logger, client, params, repo, window, branch, 5)
	if err != nil {
		return graphBundle{}, err
	}
	workflowLines := make([]seriesLine, 0, len(topWorkflows))
	for _, wf := range topWorkflows {
		points, err := queryDailyByWorkflowForBranch(ctx, logger, client, params, repo, window, branch, wf)
		if err != nil {
			return graphBundle{}, err
		}
		workflowLines = append(workflowLines, seriesLine{Name: wf, Points: points})
	}

	return graphBundle{TotalSeries: series, WorkflowLines: workflowLines}, nil
}

func queryDailyTotals(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
) ([]dayPoint, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
				},
			},
		},
		"aggs": map[string]any{
			"per_day": map[string]any{
				"date_histogram": map[string]any{
					"field":             "workflow_run_started_at",
					"calendar_interval": "1d",
					"min_doc_count":     1,
				},
				"aggs": map[string]any{
					"failures": map[string]any{
						"filter": map[string]any{
							"terms": map[string]any{"workflow_conclusion": params.FailStatus},
						},
					},
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}

	buckets, err := getBuckets(resp, "per_day")
	if err != nil {
		return nil, err
	}

	points := make([]dayPoint, 0, len(buckets))
	for _, bucket := range buckets {
		keyMillis := getInt64(bucket, "key")
		date := time.UnixMilli(keyMillis)
		total := getInt(bucket, "doc_count")
		failures := 0
		if failuresAgg, ok := bucket["failures"].(map[string]any); ok {
			failures = getInt(failuresAgg, "doc_count")
		}
		points = append(points, dayPoint{
			Date:          date,
			TotalRuns:     total,
			TotalFailures: failures,
		})
	}

	return points, nil
}

func queryDailyTotalsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
) ([]dayPoint, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermFilter("head_branch.keyword", branch),
				},
			},
		},
		"aggs": map[string]any{
			"per_day": map[string]any{
				"date_histogram": map[string]any{
					"field":             "workflow_run_started_at",
					"calendar_interval": "1d",
					"min_doc_count":     1,
				},
				"aggs": map[string]any{
					"failures": map[string]any{
						"filter": map[string]any{
							"terms": map[string]any{"workflow_conclusion": params.FailStatus},
						},
					},
				},
			},
		},
	}

	return queryDailySeries(ctx, logger, client, params.RunsIndex, query)
}

func queryTopWorkflows(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	limit int,
) ([]string, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermsFilter("workflow_conclusion", params.FailStatus),
				},
			},
		},
		"aggs": map[string]any{
			"workflows": map[string]any{
				"terms": map[string]any{
					"field": "workflow_name.keyword",
					"size":  limit,
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}

	buckets, err := getBuckets(resp, "workflows")
	if err != nil {
		return nil, err
	}

	results := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		results = append(results, getString(bucket, "key"))
	}
	return results, nil
}

func queryTopWorkflowsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
	limit int,
) ([]string, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermsFilter("workflow_conclusion", params.FailStatus),
					buildTermFilter("head_branch.keyword", branch),
				},
			},
		},
		"aggs": map[string]any{
			"workflows": map[string]any{
				"terms": map[string]any{
					"field": "workflow_name.keyword",
					"size":  limit,
				},
			},
		},
	}

	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
	if err != nil {
		return nil, err
	}

	buckets, err := getBuckets(resp, "workflows")
	if err != nil {
		return nil, err
	}

	results := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		results = append(results, getString(bucket, "key"))
	}
	return results, nil
}

func queryTopBranchWorkflows(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	limit int,
) ([]branchWorkflowPair, error) {
	var results []branchWorkflowPair
	var afterKey map[string]any

	for {
		query := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": []any{
						buildRangeFilter(window.Since, window.Until),
						buildTypeFilter("workflow_run"),
						buildRepoTermFilter(repo),
						buildEventTermsFilter(params.Events),
						buildTermsFilter("workflow_conclusion", params.FailStatus),
					},
				},
			},
			"aggs": map[string]any{
				"branch_workflow": map[string]any{
					"composite": map[string]any{
						"size": 1000,
						"sources": []any{
							map[string]any{"branch": map[string]any{"terms": map[string]any{"field": "head_branch.keyword"}}},
							map[string]any{"workflow": map[string]any{"terms": map[string]any{"field": "workflow_name.keyword"}}},
						},
					},
				},
			},
		}

		if afterKey != nil {
			query["aggs"].(map[string]any)["branch_workflow"].(map[string]any)["composite"].(map[string]any)["after"] = afterKey
		}

		addWorkflowExclusions(query)

		resp, err := doSearch(ctx, logger, client, params.RunsIndex, query)
		if err != nil {
			return nil, err
		}

		agg, err := getAgg(resp, "branch_workflow")
		if err != nil {
			return nil, err
		}

		buckets, err := getBucketArray(agg)
		if err != nil {
			return nil, err
		}

		for _, bucket := range buckets {
			keyMap := getMap(bucket, "key")
			branch := getStringFromMap(keyMap, "branch")
			workflow := getStringFromMap(keyMap, "workflow")
			count := getInt(bucket, "doc_count")
			results = append(results, branchWorkflowPair{
				Branch:   branch,
				Workflow: workflow,
				Count:    count,
			})
		}

		afterKey, _ = agg["after_key"].(map[string]any)
		if afterKey == nil {
			break
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func queryDailyByWorkflow(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	workflow string,
) ([]dayPoint, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermFilter("workflow_name.keyword", workflow),
				},
			},
		},
		"aggs": map[string]any{
			"per_day": map[string]any{
				"date_histogram": map[string]any{
					"field":             "workflow_run_started_at",
					"calendar_interval": "1d",
					"min_doc_count":     1,
				},
				"aggs": map[string]any{
					"failures": map[string]any{
						"filter": map[string]any{
							"terms": map[string]any{"workflow_conclusion": params.FailStatus},
						},
					},
				},
			},
		},
	}

	return queryDailySeries(ctx, logger, client, params.RunsIndex, query)
}

func queryDailyByWorkflowForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
	workflow string,
) ([]dayPoint, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermFilter("workflow_name.keyword", workflow),
					buildTermFilter("head_branch.keyword", branch),
				},
			},
		},
		"aggs": map[string]any{
			"per_day": map[string]any{
				"date_histogram": map[string]any{
					"field":             "workflow_run_started_at",
					"calendar_interval": "1d",
					"min_doc_count":     1,
				},
				"aggs": map[string]any{
					"failures": map[string]any{
						"filter": map[string]any{
							"terms": map[string]any{"workflow_conclusion": params.FailStatus},
						},
					},
				},
			},
		},
	}

	return queryDailySeries(ctx, logger, client, params.RunsIndex, query)
}

func queryDailyByBranchWorkflow(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *reportParams,
	repo string,
	window reportWindow,
	branch string,
	workflow string,
) ([]dayPoint, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					buildRangeFilter(window.Since, window.Until),
					buildTypeFilter("workflow_run"),
					buildRepoTermFilter(repo),
					buildEventTermsFilter(params.Events),
					buildTermFilter("workflow_name.keyword", workflow),
					buildTermFilter("head_branch.keyword", branch),
				},
			},
		},
		"aggs": map[string]any{
			"per_day": map[string]any{
				"date_histogram": map[string]any{
					"field":             "workflow_run_started_at",
					"calendar_interval": "1d",
					"min_doc_count":     1,
				},
				"aggs": map[string]any{
					"failures": map[string]any{
						"filter": map[string]any{
							"terms": map[string]any{"workflow_conclusion": params.FailStatus},
						},
					},
				},
			},
		},
	}

	return queryDailySeries(ctx, logger, client, params.RunsIndex, query)
}

func queryDailySeries(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	index string,
	query map[string]any,
) ([]dayPoint, error) {
	addWorkflowExclusions(query)

	resp, err := doSearch(ctx, logger, client, index, query)
	if err != nil {
		return nil, err
	}

	buckets, err := getBuckets(resp, "per_day")
	if err != nil {
		return nil, err
	}

	points := make([]dayPoint, 0, len(buckets))
	for _, bucket := range buckets {
		keyMillis := getInt64(bucket, "key")
		date := time.UnixMilli(keyMillis)
		total := getInt(bucket, "doc_count")
		failures := 0
		if failuresAgg, ok := bucket["failures"].(map[string]any); ok {
			failures = getInt(failuresAgg, "doc_count")
		}
		points = append(points, dayPoint{Date: date, TotalRuns: total, TotalFailures: failures})
	}

	return points, nil
}

// Markdown helpers

func renderLinks(links []reportLink) string {
	if len(links) == 0 {
		return ""
	}
	entries := make([]string, 0, len(links))
	for _, link := range links {
		parts := make([]string, 0, 2)
		if link.Workflow != "" {
			label := "run"
			runID := link.RunID
			if runID == 0 {
				runID = parseRunID(link.Workflow)
			}
			if runID > 0 {
				label = fmt.Sprintf("run#%d", runID)
			} else if link.RunNumber > 0 {
				label = fmt.Sprintf("run#%d", link.RunNumber)
			}
			parts = append(parts, fmt.Sprintf("[%s](%s)", label, link.Workflow))
		}
		if link.Job != "" {
			parts = append(parts, fmt.Sprintf("[job](%s)", link.Job))
		}
		if len(parts) > 0 {
			entries = append(entries, strings.Join(parts, " / "))
		}
	}
	return strings.Join(entries, ", ")
}

func formatOwners(testOwners, suiteOwners []string) string {
	parts := []string{}
	if len(testOwners) > 0 {
		parts = append(parts, fmt.Sprintf("test: %s", strings.Join(testOwners, ", ")))
	}
	if len(suiteOwners) > 0 {
		parts = append(parts, fmt.Sprintf("suite: %s", strings.Join(suiteOwners, ", ")))
	}
	return strings.Join(parts, " | ")
}

func escapePipes(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// OpenSearch helpers

func doSearch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	index string,
	query map[string]any,
) (map[string]any, error) {
	payload, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal query: %w", err)
	}

	req := opensearchapi.SearchRequest{
		Index: []string{index},
		Body:  bytes.NewReader(payload),
	}

	resp, err := req.Do(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("opensearch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.IsError() {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("opensearch error: %s", body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response: %w", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("unable to parse response: %w", err)
	}

	logger.Debug("OpenSearch response", "response", string(body))
	return parsed, nil
}

func buildRangeFilter(since, until time.Time) map[string]any {
	return map[string]any{
		"range": map[string]any{
			"workflow_run_started_at": map[string]any{
				"gte":    since.Format("2006-01-02"),
				"lte":    until.Format("2006-01-02"),
				"format": "yyyy-MM-dd",
			},
		},
	}
}

func buildTypeFilter(docType string) map[string]any {
	return map[string]any{"term": map[string]any{"type.keyword": docType}}
}

func buildRepoTermFilter(repo string) map[string]any {
	return map[string]any{"term": map[string]any{"repository.full_name.keyword": repo}}
}

func buildEventTermsFilter(events []string) map[string]any {
	return map[string]any{"terms": map[string]any{"event.keyword": events}}
}

func buildTermFilter(field string, value string) map[string]any {
	return map[string]any{"term": map[string]any{field: value}}
}

func buildTermsFilter(field string, values []string) map[string]any {
	return map[string]any{"terms": map[string]any{field: values}}
}

func buildWorkflowExclusionFilters() []any {
	return []any{
		map[string]any{"wildcard": map[string]any{"workflow_name.keyword": "Ariane*"}},
		map[string]any{"term": map[string]any{"workflow_name.keyword": "Renovate"}},
	}
}

func addWorkflowExclusions(query map[string]any) {
	queryBlock, ok := query["query"].(map[string]any)
	if !ok {
		return
	}
	boolBlock, ok := queryBlock["bool"].(map[string]any)
	if !ok {
		return
	}
	boolBlock["must_not"] = buildWorkflowExclusionFilters()
}

func buildTopHitsAgg(size int) map[string]any {
	return map[string]any{
		"top_hits": map[string]any{
			"size": size,
			"sort": []any{map[string]any{"workflow_run_started_at": map[string]any{"order": "desc"}}},
			"_source": map[string]any{
				"includes": []string{
					"workflow_link",
					"workflow_run_number",
					"workflow_id",
					"job_link",
					"test_case_owners",
					"test_suite_owners",
					"test_suite_name",
				},
			},
		},
	}
}

func getAgg(resp map[string]any, name string) (map[string]any, error) {
	aggs, ok := resp["aggregations"].(map[string]any)
	if !ok {
		return nil, errors.New("missing aggregations")
	}
	agg, ok := aggs[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing aggregation %s", name)
	}
	return agg, nil
}

func getBuckets(resp map[string]any, name string) ([]map[string]any, error) {
	agg, err := getAgg(resp, name)
	if err != nil {
		return nil, err
	}
	return getBucketArray(agg)
}

func getTermKeys(resp map[string]any, name string) ([]string, error) {
	buckets, err := getBuckets(resp, name)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		key := getString(bucket, "key")
		if key != "" {
			keys = append(keys, key)
		}
	}
	return uniqueSorted(keys), nil
}

func getBucketArray(agg map[string]any) ([]map[string]any, error) {
	bucketsAny, ok := agg["buckets"].([]any)
	if !ok {
		return nil, errors.New("missing buckets")
	}
	buckets := make([]map[string]any, 0, len(bucketsAny))
	for _, item := range bucketsAny {
		bucket, ok := item.(map[string]any)
		if !ok {
			continue
		}
		buckets = append(buckets, bucket)
	}
	return buckets, nil
}

func getString(bucket map[string]any, key string) string {
	if val, ok := bucket[key].(string); ok {
		return val
	}
	return ""
}

func getStringFromMap(m map[string]any, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getIntFromMap(m map[string]any, key string) int {
	if val, ok := m[key].(float64); ok {
		return int(val)
	}
	if val, ok := m[key].(int); ok {
		return val
	}
	if val, ok := m[key].(int64); ok {
		return int(val)
	}
	return 0
}

func getInt64FromMap(m map[string]any, key string) int64 {
	if val, ok := m[key].(float64); ok {
		return int64(val)
	}
	if val, ok := m[key].(int64); ok {
		return val
	}
	if val, ok := m[key].(int); ok {
		return int64(val)
	}
	return 0
}

func getInt(bucket map[string]any, key string) int {
	if val, ok := bucket[key].(float64); ok {
		return int(val)
	}
	if val, ok := bucket[key].(int); ok {
		return val
	}
	return 0
}

func getInt64(bucket map[string]any, key string) int64 {
	if val, ok := bucket[key].(float64); ok {
		return int64(val)
	}
	if val, ok := bucket[key].(int64); ok {
		return val
	}
	return 0
}

func getMap(bucket map[string]any, key string) map[string]any {
	if val, ok := bucket[key].(map[string]any); ok {
		return val
	}
	return map[string]any{}
}

func extractLinksFromBucket(bucket map[string]any, maxLinks int) []reportLink {
	hits := extractTopHits(bucket)
	return extractLinksFromHits(hits, maxLinks)
}

func extractOwnersFromBucket(bucket map[string]any) ([]string, []string) {
	hits := extractTopHits(bucket)
	owners, suiteOwners, _ := extractOwnersFromHits(hits)
	return owners, suiteOwners
}

func extractFailureGroupDetails(bucket map[string]any, maxLinks int) ([]reportLink, []string, []string) {
	hits := extractTopHits(bucket)
	links := extractLinksFromHits(hits, maxLinks)
	owners, suiteOwners, _ := extractOwnersFromHits(hits)
	return links, owners, suiteOwners
}

func extractTopHits(bucket map[string]any) []map[string]any {
	sample, ok := bucket["sample"].(map[string]any)
	if !ok {
		return nil
	}
	hitsWrapper, ok := sample["hits"].(map[string]any)
	if !ok {
		return nil
	}
	hitsAny, ok := hitsWrapper["hits"].([]any)
	if !ok {
		return nil
	}
	results := make([]map[string]any, 0, len(hitsAny))
	for _, item := range hitsAny {
		hit, ok := item.(map[string]any)
		if !ok {
			continue
		}
		results = append(results, hit)
	}
	return results
}

func extractLinksFromHits(hits []map[string]any, maxLinks int) []reportLink {
	links := []reportLink{}
	for _, hit := range hits {
		source, ok := hit["_source"].(map[string]any)
		if !ok {
			continue
		}
		workflow := getStringFromMap(source, "workflow_link")
		job := getStringFromMap(source, "job_link")
		runNumber := getIntFromMap(source, "workflow_run_number")
		runID := getInt64FromMap(source, "workflow_id")
		if workflow == "" && job == "" {
			continue
		}
		link := reportLink{Workflow: workflow, Job: job, RunNumber: runNumber, RunID: runID}
		links = append(links, link)
		if len(links) >= maxLinks {
			break
		}
	}
	return links
}

func extractOwnersFromHits(hits []map[string]any) ([]string, []string, []string) {
	owners := []string{}
	suiteOwners := []string{}
	suites := []string{}
	for _, hit := range hits {
		source, ok := hit["_source"].(map[string]any)
		if !ok {
			continue
		}
		owners = append(owners, extractStringSlice(source, "test_case_owners")...)
		suiteOwners = append(suiteOwners, extractStringSlice(source, "test_suite_owners")...)
		if name := getStringFromMap(source, "test_suite_name"); name != "" {
			suites = append(suites, name)
		}
	}
	return owners, suiteOwners, suites
}

func extractStringSlice(source map[string]any, key string) []string {
	val, ok := source[key]
	if !ok {
		return nil
	}
	items, ok := val.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if ok {
			result = append(result, s)
		}
	}
	return result
}

func mergeLinks(existing, incoming []reportLink, limit int) []reportLink {
	seen := map[string]struct{}{}
	result := make([]reportLink, 0, limit)
	for _, link := range existing {
		key := link.Workflow + "|" + link.Job
		seen[key] = struct{}{}
		result = append(result, link)
	}
	for _, link := range incoming {
		key := link.Workflow + "|" + link.Job
		if _, ok := seen[key]; ok {
			continue
		}
		result = append(result, link)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func mergeStrings(existing, incoming []string) []string {
	result := append(existing[:0:0], existing...)
	result = append(result, incoming...)
	return result
}

func uniqueSorted(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := map[string]struct{}{}
	for _, item := range items {
		seen[item] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for item := range seen {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// Normalization

var (
	reTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?`)
	reUUID      = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reIP        = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	reHex       = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	reLongNum   = regexp.MustCompile(`\b\d{5,}\b`)
	reSpace     = regexp.MustCompile(`\s+`)
)

func normalizeFailureMessage(input string) string {
	out := reTimestamp.ReplaceAllString(input, "<ts>")
	out = reUUID.ReplaceAllString(out, "<uuid>")
	out = reIP.ReplaceAllString(out, "<ip>")
	out = reHex.ReplaceAllString(out, "<hex>")
	out = reLongNum.ReplaceAllString(out, "<num>")
	out = strings.TrimSpace(out)
	out = reSpace.ReplaceAllString(out, " ")
	return out
}

func slugify(input string) string {
	slug := strings.ToLower(input)
	slug = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "unknown"
	}
	return slug
}

func parseRunID(link string) int64 {
	matches := regexp.MustCompile(`/actions/runs/([0-9]+)`).FindStringSubmatch(link)
	if len(matches) < 2 {
		return 0
	}
	value, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func componentFromRepo(repo string) string {
	parts := strings.Split(repo, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return slugify(repo)
}

func reportOutputPath(outputDir, component string) string {
	return filepath.Join(outputDir, component, "README.md")
}

func branchReportOutputPath(outputDir, component, branch string) string {
	return filepath.Join(outputDir, component, "branch", slugify(branch), "README.md")
}

func filterBranchesByPrefix(branches []string) ([]string, []string) {
	mainBranches := make([]string, 0, len(branches))
	otherBranches := make([]string, 0, len(branches))
	for _, branch := range branches {
		if isMainBranch(branch) {
			mainBranches = append(mainBranches, branch)
		} else {
			otherBranches = append(otherBranches, branch)
		}
	}
	sort.Strings(mainBranches)
	sort.Strings(otherBranches)
	return mainBranches, otherBranches
}

func buildOtherBranchLinks(component string, branches []string) []branchLink {
	if len(branches) == 0 {
		return nil
	}
	sorted := append([]string(nil), branches...)
	sort.Strings(sorted)
	links := make([]branchLink, 0, len(sorted))
	for _, branch := range sorted {
		links = append(links, branchLink{
			Name: branch,
			Path: filepath.ToSlash(filepath.Join("branch", slugify(branch))) + "/",
		})
	}
	return links
}

func isMainBranch(branch string) bool {
	return strings.HasPrefix(branch, "main")
}

// Graph rendering

type svgChart struct {
	Width  int
	Height int
	Pad    int
}

func graphPrefix(slug string, days int) string {
	return fmt.Sprintf("%s-%dd", slug, days)
}

func branchGraphPrefix(slug string, days int, branch string) string {
	return fmt.Sprintf("%s-%dd-%s", slug, days, slugify(branch))
}

func writeGraphBundle(graphDir, prefix string, graphs graphBundle) error {
	if err := writeSVG(filepath.Join(graphDir, fmt.Sprintf("%s-total.svg", prefix)),
		renderTotalsChart(graphs.TotalSeries, "Total failures vs runs")); err != nil {
		return err
	}
	if err := writeSVG(filepath.Join(graphDir, fmt.Sprintf("%s-workflows.svg", prefix)),
		renderSeriesChart(graphs.WorkflowLines, "Failures per workflow")); err != nil {
		return err
	}
	if len(graphs.BranchLines) > 0 {
		if err := writeSVG(filepath.Join(graphDir, fmt.Sprintf("%s-branches.svg", prefix)),
			renderSeriesChart(graphs.BranchLines, "Failures per branch and workflow")); err != nil {
			return err
		}
	}
	return nil
}

func writeSVG(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func writeWorkflowBars(graphDir, prefix string, bars []workflowBar) error {
	path := filepath.Join(graphDir, fmt.Sprintf("%s-workflow-bars.svg", prefix))
	content := renderBarChart("Workflow runs vs failures", toWorkflowBarSeries(bars), true)
	return writeSVG(path, content)
}

type barSeries struct {
	Label      string
	TotalRuns  int
	TotalFails int
}

func toWorkflowBarSeries(bars []workflowBar) []barSeries {
	series := make([]barSeries, 0, len(bars))
	for _, b := range bars {
		series = append(series, barSeries{
			Label:      b.Workflow,
			TotalRuns:  b.TotalRuns,
			TotalFails: b.TotalFails,
		})
	}
	return series
}

func renderBarChart(title string, series []barSeries, extraLabelSpace bool) string {
	chart := svgChart{Width: 1100, Height: 360, Pad: 50}
	padLeft := 60
	padRight := 40
	padTop := 60
	padBottom := 60
	labelAngle := 55.0
	if extraLabelSpace {
		chart.Height = 520
		padTop = 70
		padBottom = 120
	}
	if extraLabelSpace && len(series) > 0 {
		maxLabelChars := 0
		for _, item := range series {
			if n := len(item.Label); n > maxLabelChars {
				maxLabelChars = n
			}
		}
		// Approximate text width for sizing/padding to avoid clipping rotated labels.
		maxLabelWidthPx := float64(maxLabelChars) * 6.0
		angleRad := labelAngle * math.Pi / 180.0
		labelHoriz := int(math.Ceil(math.Cos(angleRad)*maxLabelWidthPx)) + 24
		labelVert := int(math.Ceil(math.Sin(angleRad)*maxLabelWidthPx)) + 44
		if labelHoriz > padRight {
			padRight = labelHoriz
		}
		if labelVert > padBottom {
			padBottom = labelVert
		}
		minPlotWidth := int(math.Ceil(float64(len(series)) * 36.0))
		minWidth := padLeft + padRight + minPlotWidth
		if minWidth > chart.Width {
			chart.Width = minWidth
		}
		minHeight := padTop + padBottom + 260
		if minHeight > chart.Height {
			chart.Height = minHeight
		}
	}
	width := chart.Width
	height := chart.Height

	var b strings.Builder
	b.WriteString(fmt.Sprintf("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\">", width, height))
	b.WriteString(fmt.Sprintf("<rect width=\"100%%\" height=\"100%%\" fill=\"white\"/>"))
	b.WriteString(fmt.Sprintf("<text x=\"%d\" y=\"%d\" font-size=\"14\" font-family=\"sans-serif\">%s</text>", padLeft, padTop-30, title))

	if len(series) == 0 {
		b.WriteString("</svg>")
		return b.String()
	}

	maxVal := 1
	for _, item := range series {
		if item.TotalRuns > maxVal {
			maxVal = item.TotalRuns
		}
	}

	plotWidth := float64(width - padLeft - padRight)
	plotHeight := float64(height - padTop - padBottom)
	barWidth := plotWidth / float64(len(series))

	// Axes
	x0 := padLeft
	y0 := height - padBottom
	x1 := width - padRight
	y1 := padTop
	b.WriteString(fmt.Sprintf("<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"#1f2937\" stroke-width=\"1\"/>", x0, y0, x1, y0))
	b.WriteString(fmt.Sprintf("<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"#1f2937\" stroke-width=\"1\"/>", x0, y0, x0, y1))

	for i, item := range series {
		x := float64(padLeft) + barWidth*float64(i) + barWidth*0.1
		widthPx := barWidth * 0.8
		runsHeight := (float64(item.TotalRuns) / float64(maxVal)) * plotHeight
		failsHeight := (float64(item.TotalFails) / float64(maxVal)) * plotHeight
		yRuns := float64(y0) - runsHeight
		yFails := float64(y0) - failsHeight

		b.WriteString(fmt.Sprintf("<rect x=\"%.2f\" y=\"%.2f\" width=\"%.2f\" height=\"%.2f\" fill=\"#2563eb\" fill-opacity=\"0.35\"/>", x, yRuns, widthPx, runsHeight))
		b.WriteString(fmt.Sprintf("<rect x=\"%.2f\" y=\"%.2f\" width=\"%.2f\" height=\"%.2f\" fill=\"#ef4444\" fill-opacity=\"0.8\"/>", x, yFails, widthPx, failsHeight))

		label := item.Label
		labelY := y0 + 30
		b.WriteString(fmt.Sprintf("<text x=\"%.2f\" y=\"%d\" font-size=\"10\" font-family=\"sans-serif\" text-anchor=\"start\" transform=\"rotate(55 %.2f,%d)\">%s</text>",
			x, labelY, x, labelY, escapeXML(label)))
	}

	b.WriteString("</svg>")
	return b.String()
}

func renderTotalsChart(points []dayPoint, title string) string {
	chart := svgChart{Width: 900, Height: 320, Pad: 40}
	series := []seriesLine{
		{Name: "Failures", Points: points},
		{Name: "Runs", Points: points},
	}
	return renderMultiSeriesChart(chart, title, series, func(p dayPoint, idx int) float64 {
		if idx == 0 {
			return float64(p.TotalFailures)
		}
		return float64(p.TotalRuns)
	})
}

func renderSeriesChart(lines []seriesLine, title string) string {
	chart := svgChart{Width: 900, Height: 320, Pad: 40}
	return renderMultiSeriesChart(chart, title, lines, func(p dayPoint, _ int) float64 {
		return float64(p.TotalFailures)
	})
}

func renderMultiSeriesChart(chart svgChart, title string, lines []seriesLine, valueFn func(dayPoint, int) float64) string {
	width := chart.Width
	height := chart.Height
	pad := chart.Pad
	titlePad := 26
	topPad := pad + titlePad + 8
	bottomPad := pad + 20
	leftPad := pad + 10
	rightPad := pad

	maxVal := 1.0
	minDate, maxDate := time.Time{}, time.Time{}
	for i, line := range lines {
		for _, point := range line.Points {
			val := valueFn(point, i)
			if val > maxVal {
				maxVal = val
			}
			if minDate.IsZero() || point.Date.Before(minDate) {
				minDate = point.Date
			}
			if maxDate.IsZero() || point.Date.After(maxDate) {
				maxDate = point.Date
			}
		}
	}

	if minDate.IsZero() || maxDate.IsZero() {
		minDate = time.Now().AddDate(0, 0, -1)
		maxDate = time.Now()
	}

	colors := []string{"#ef4444", "#2563eb", "#16a34a", "#f59e0b", "#7c3aed"}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\">", width, height))
	b.WriteString(fmt.Sprintf("<rect width=\"100%%\" height=\"100%%\" fill=\"white\"/>"))
	b.WriteString(fmt.Sprintf("<text x=\"%d\" y=\"%d\" font-size=\"14\" font-family=\"sans-serif\">%s</text>", leftPad, pad-8, title))

	plotWidth := float64(width - leftPad - rightPad)
	plotHeight := float64(height - topPad - bottomPad)

	drawAxes(&b, leftPad, rightPad, topPad, bottomPad, width, height, minDate, maxDate, maxVal, plotWidth, plotHeight)

	for i, line := range lines {
		if len(line.Points) == 0 {
			continue
		}
		color := colors[i%len(colors)]
		var path strings.Builder
		for idx, point := range line.Points {
			x := leftPad + int(scaleTime(point.Date, minDate, maxDate, plotWidth))
			y := topPad + int(plotHeight-scaleValue(valueFn(point, i), maxVal, plotHeight))
			if idx == 0 {
				path.WriteString(fmt.Sprintf("M %d %d", x, y))
			} else {
				path.WriteString(fmt.Sprintf(" L %d %d", x, y))
			}
		}
		b.WriteString(fmt.Sprintf("<path d=\"%s\" fill=\"none\" stroke=\"%s\" stroke-width=\"2\"/>", path.String(), color))
		b.WriteString(fmt.Sprintf("<text x=\"%d\" y=\"%d\" font-size=\"11\" font-family=\"sans-serif\" fill=\"%s\">%s</text>",
			leftPad+10, topPad+12+(i*12), color, escapeXML(line.Name)))
	}

	b.WriteString("</svg>")
	return b.String()
}

func drawAxes(
	b *strings.Builder,
	leftPad int,
	rightPad int,
	topPad int,
	bottomPad int,
	width int,
	height int,
	minDate time.Time,
	maxDate time.Time,
	maxVal float64,
	plotWidth float64,
	plotHeight float64,
) {
	x0 := leftPad
	y0 := height - bottomPad
	x1 := width - rightPad
	y1 := topPad

	b.WriteString(fmt.Sprintf("<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"#1f2937\" stroke-width=\"1\"/>", x0, y0, x1, y0))
	b.WriteString(fmt.Sprintf("<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"#1f2937\" stroke-width=\"1\"/>", x0, y0, x0, y1))
	b.WriteString(fmt.Sprintf("<text x=\"%d\" y=\"%d\" font-size=\"10\" font-family=\"sans-serif\">Failures</text>", x0, y1-8))

	totalDays := int(maxDate.Sub(minDate).Hours()/24) + 1
	stepDays := totalDays / 6
	if stepDays < 1 {
		stepDays = 1
	}

	for day := 0; day <= totalDays; day += stepDays {
		tickDate := minDate.AddDate(0, 0, day)
		x := x0 + int(scaleTime(tickDate, minDate, maxDate, plotWidth))
		b.WriteString(fmt.Sprintf("<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"#9ca3af\" stroke-width=\"1\"/>", x, y0, x, y0+4))
		label := tickDate.Format("Jan-02")
		b.WriteString(fmt.Sprintf("<text x=\"%d\" y=\"%d\" font-size=\"10\" font-family=\"sans-serif\" text-anchor=\"middle\">%s</text>", x, y0+18, label))
	}

	yTicks := []float64{0, maxVal / 2, maxVal}
	for _, val := range yTicks {
		y := y0 - int(scaleValue(val, maxVal, plotHeight))
		b.WriteString(fmt.Sprintf("<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"#e5e7eb\" stroke-width=\"1\"/>", x0, y, x1, y))
		b.WriteString(fmt.Sprintf("<text x=\"%d\" y=\"%d\" font-size=\"10\" font-family=\"sans-serif\" text-anchor=\"end\">%d</text>", x0-6, y+4, int(val)))
	}
}

func scaleValue(value, maxVal, height float64) float64 {
	if maxVal <= 0 {
		return 0
	}
	return (value / maxVal) * height
}

func scaleTime(t, min, max time.Time, width float64) float64 {
	minUnix := float64(min.Unix())
	maxUnix := float64(max.Unix())
	if math.Abs(maxUnix-minUnix) < 1 {
		return 0
	}
	return ((float64(t.Unix()) - minUnix) / (maxUnix - minUnix)) * width
}

func escapeXML(input string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
	)
	return replacer.Replace(input)
}
