package report

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/isovalent/corgi/pkg/log"
	ops "github.com/isovalent/corgi/pkg/opensearch"
	"github.com/opensearch-project/opensearch-go"
	"github.com/opensearch-project/opensearch-go/opensearchapi"
)

type Params struct {
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
	Name           string
	Path           string
	FailureSummary string
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

//go:embed templates/*.tmpl
var reportTemplates embed.FS

var reportTemplate = template.Must(template.New("report.md.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	templateReportPath,
))

var landingTemplate = template.Must(template.New("landing.md.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	templateLandingPath,
))

var branchTemplate = template.Must(template.New("branch.md.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	templateBranchPath,
))

func DefaultParams() Params {
	return Params{
		RunsIndex:  defaultRunsIndex,
		Repos:      append([]string(nil), defaultRepos...),
		Events:     append([]string(nil), defaultEvents...),
		Top:        defaultTop,
		Days:       append([]int(nil), defaultDays...),
		MaxLinks:   defaultMaxLinks,
		FailStatus: append([]string(nil), defaultFailStatus...),
		TestStatus: append([]string(nil), defaultTestStatus...),
	}
}

func ValidateParams(params *Params) error {
	if params == nil {
		return errors.New("params are required")
	}
	if params.OutputDir == "" {
		return errors.New("--output-dir is required")
	}
	if params.Top <= 0 {
		return errors.New("--top must be greater than 0")
	}
	if params.MaxLinks <= 0 {
		return errors.New("--max-links must be greater than 0")
	}
	if params.RunsIndex == "" {
		return errors.New("--runs-index is required")
	}
	if len(params.Repos) == 0 {
		return errors.New("--repositories is required")
	}
	if len(params.Events) == 0 {
		return errors.New("--events is required")
	}
	return nil
}

func Run(ctx context.Context, params *Params) error {
	if err := ValidateParams(params); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	logger := log.NewLogger(params.Verbose)

	opensearchCfg := ops.NewClientConfig()
	client, err := opensearch.NewClient(opensearchCfg)
	if err != nil {
		return fmt.Errorf("unable to create OpenSearch client: %w", err)
	}

	reportSpecs := append([]reportSpec(nil), defaultReportSpecs...)

	now := time.Now().Local()
	windows := buildReportWindows(now, params.Days)

	landingLinks := make([]landingLink, 0, len(reportSpecs))

	for _, spec := range reportSpecs {
		if !slices.Contains(params.Repos, spec.Repository) {
			logger.Debug("Skipping repository not requested", "repo", spec.Repository)
			continue
		}

		reportStart := time.Now()
		results := make([]reportResult, 0, len(windows))
		branchResults := make(map[string][]branchWindowResult)
		for _, window := range windows {
			windowResult, err := buildReportWindow(ctx, logger, client, params, spec.Repository, window)
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

		if err := renderReportFile(params.OutputDir, spec, results, reportStart); err != nil {
			return err
		}

		for branch, branchWindowResults := range branchResults {
			if err := renderBranchReportFile(params.OutputDir, spec, branch, branchWindowResults, reportStart); err != nil {
				return err
			}
		}
	}

	if err := renderLandingPage(params.OutputDir, landingLinks); err != nil {
		return err
	}

	return nil
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
	params *Params,
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
		OtherBranches:                 buildOtherBranchLinks(otherBranchResults),
	}, nil
}

func buildBranchResult(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
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
	if err := writeReportCSS(reportDir); err != nil {
		return err
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
	componentDir := filepath.Join(outputDir, spec.Component)

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
	if err := writeReportCSS(componentDir); err != nil {
		return err
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
	path := filepath.Join(outputDir, readmeFileName)
	var b strings.Builder
	data := landingTemplateData{Links: links}
	if err := landingTemplate.Execute(&b, data); err != nil {
		return fmt.Errorf("unable to render landing template: %w", err)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeReportCSS(reportDir string) error {
	content, err := reportTemplates.ReadFile(templateReportCSS)
	if err != nil {
		return fmt.Errorf("unable to read report css template: %w", err)
	}
	path := filepath.Join(reportDir, reportCSSName)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("unable to write report css file %s: %w", path, err)
	}
	return nil
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
	return fmt.Sprintf(windowTitleFmt,
		window.Days,
		window.Since.Format(windowDateLayout),
		window.Until.Format(windowDateLayout),
	)
}

func windowTag(window reportWindow) string {
	return fmt.Sprintf(windowTagFmt, window.Days)
}

func reportTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"windowTitle":           windowTitle,
		"windowTag":             windowTag,
		"graphPrefix":           graphPrefix,
		"branchGraphPrefix":     branchGraphPrefix,
		"escapePipes":           escapePipes,
		"escapeXML":             html.EscapeString,
		"renderLinks":           renderLinks,
		"formatTrendComparison": formatTrendComparison,
		"join":                  strings.Join,
		"add1": func(value int) int {
			return value + 1
		},
		"formatFailureRate": formatFailureRate,
		"formatFailureStat": formatFailureStat,
		"chartTitleTotal": func() string {
			return chartTitleTotalFailures
		},
		"chartTitleWf": func() string {
			return chartTitleWorkflowFailures
		},
		"chartTitleBranch": func() string {
			return chartTitleBranchWorkflowFails
		},
		"chartTitleBars": func() string {
			return chartTitleWorkflowRunFailures
		},
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
	return fmt.Sprintf(failureRateFmt, totalFailures, totalRuns, percent)
}

func formatFailureStat(failures, totalRuns int) string {
	percent := 0.0
	if totalRuns > 0 {
		percent = (float64(failures) / float64(totalRuns)) * 100
	}
	return fmt.Sprintf(failureStatFmt, failures, totalRuns, percent)
}

func failureRatePercent(failures, totalRuns int) float64 {
	if totalRuns <= 0 {
		return 0
	}
	return (float64(failures) / float64(totalRuns)) * 100
}

func formatTrendComparison(previous, previousTotalRuns, current, currentTotalRuns int) string {
	previousPercent := failureRatePercent(previous, previousTotalRuns)
	currentPercent := failureRatePercent(current, currentTotalRuns)
	return fmt.Sprintf(
		"%.1f%%(%d/%d) -> %.1f%%(%d/%d)",
		previousPercent,
		previous,
		previousTotalRuns,
		currentPercent,
		current,
		currentTotalRuns,
	)
}

func queryWorkflowRunTotals(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
) (map[string]int, error) {
	return queryWorkflowRunTotalsWithExtraFilters(ctx, logger, client, params, repo, window)
}

func queryWorkflowRunTotalsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
	branch string,
) (map[string]int, error) {
	return queryWorkflowRunTotalsWithExtraFilters(
		ctx,
		logger,
		client,
		params,
		repo,
		window,
		buildTermFilter("head_branch.keyword", branch),
	)
}

func queryWorkflowRunTotalsWithExtraFilters(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
	extraMust ...any,
) (map[string]int, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": buildWorkflowRunMust(window, repo, params.Events, extraMust...),
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
	params *Params,
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
					"must": buildWorkflowRunMust(window, repo, params.Events),
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
	params *Params,
	repo string,
	window reportWindow,
) ([]workflowCount, error) {
	return queryWorkflowFailuresWithBranch(ctx, logger, client, params, repo, window, "")
}

func queryWorkflowFailuresForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
	branch string,
) ([]workflowCount, error) {
	return queryWorkflowFailuresWithBranch(ctx, logger, client, params, repo, window, branch)
}

func queryWorkflowFailuresWithBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
	branch string,
) ([]workflowCount, error) {
	must := buildWorkflowRunMust(window, repo, params.Events, buildTermsFilter("workflow_conclusion", params.FailStatus))
	if branch != "" {
		must = append(must, buildTermFilter("head_branch.keyword", branch))
	}

	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": must,
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
		links, testOwners, suiteOwners, _ := extractBucketDetails(bucket, params.MaxLinks)
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
	params *Params,
	repo string,
	window reportWindow,
) ([]string, error) {
	query := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": map[string]any{
				"must": buildWorkflowRunMust(
					window, repo, params.Events, buildTermsFilter("workflow_conclusion", params.FailStatus),
				),
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
	Workflow          string
	Label             string
	Current           int
	CurrentTotalRuns  int
	Previous          int
	PreviousTotalRuns int
	Status            string
}

func buildTrends(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
) ([]trendItem, error) {
	return buildTrendsForWindow(
		params.Top,
		window,
		func(w reportWindow) ([]reportGroup, error) {
			return queryFailureGroups(ctx, logger, client, params, repo, w)
		},
		func(w reportWindow) (map[string]int, error) {
			return queryWorkflowRunTotals(ctx, logger, client, params, repo, w)
		},
	)
}

func buildTrendsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
	branch string,
) ([]trendItem, error) {
	return buildTrendsForWindow(
		params.Top,
		window,
		func(w reportWindow) ([]reportGroup, error) {
			return queryFailureGroupsForBranch(ctx, logger, client, params, repo, w, branch)
		},
		func(w reportWindow) (map[string]int, error) {
			return queryWorkflowRunTotalsForBranch(ctx, logger, client, params, repo, w, branch)
		},
	)
}

func buildTrendsForWindow(
	top int,
	window reportWindow,
	queryGroupsFn func(reportWindow) ([]reportGroup, error),
	queryRunTotalsFn func(reportWindow) (map[string]int, error),
) ([]trendItem, error) {
	current, err := queryGroupsFn(window)
	if err != nil {
		return nil, err
	}

	prevWindow := reportWindow{
		Since: window.Since.AddDate(0, 0, -window.Days),
		Until: window.Since,
		Days:  window.Days,
	}
	previous, err := queryGroupsFn(prevWindow)
	if err != nil {
		return nil, err
	}
	currentRunTotals, err := queryRunTotalsFn(window)
	if err != nil {
		return nil, err
	}
	previousRunTotals, err := queryRunTotalsFn(prevWindow)
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
		currentTotalRuns := currentRunTotals[item.Workflow]
		previousTotalRuns := previousRunTotals[item.Workflow]
		currentRate := failureRatePercent(item.Count, currentTotalRuns)
		previousRate := failureRatePercent(prev, previousTotalRuns)
		status := "🟠"
		if currentRate < previousRate {
			status = "🟢"
		} else if currentRate > previousRate {
			status = "🔴"
		}
		label := fmt.Sprintf("`%s` `%s`", item.TestCaseName, item.FailureMessage)
		trends = append(trends, trendItem{
			Workflow:          item.Workflow,
			Label:             label,
			Current:           item.Count,
			CurrentTotalRuns:  currentTotalRuns,
			Previous:          prev,
			PreviousTotalRuns: previousTotalRuns,
			Status:            status,
		})
	}

	sort.Slice(trends, func(i, j int) bool {
		leftCurrentRate := failureRatePercent(trends[i].Current, trends[i].CurrentTotalRuns)
		rightCurrentRate := failureRatePercent(trends[j].Current, trends[j].CurrentTotalRuns)
		if leftCurrentRate != rightCurrentRate {
			return leftCurrentRate > rightCurrentRate
		}
		leftPreviousRate := failureRatePercent(trends[i].Previous, trends[i].PreviousTotalRuns)
		rightPreviousRate := failureRatePercent(trends[j].Previous, trends[j].PreviousTotalRuns)
		if leftPreviousRate != rightPreviousRate {
			return leftPreviousRate > rightPreviousRate
		}
		if trends[i].Current != trends[j].Current {
			return trends[i].Current > trends[j].Current
		}
		if trends[i].Previous != trends[j].Previous {
			return trends[i].Previous > trends[j].Previous
		}
		if trends[i].Workflow != trends[j].Workflow {
			return trends[i].Workflow < trends[j].Workflow
		}
		return trends[i].Label < trends[j].Label
	})
	if len(trends) > top {
		trends = trends[:top]
	}

	return trends, nil
}

func queryWorkflowFailureMeta(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
	workflow string,
	branch string,
) ([]string, []string, []string, error) {
	must := buildTestCaseFailureMust(
		window,
		repo,
		params.Events,
		params.TestStatus,
		buildTermFilter("workflow_name.keyword", workflow),
	)
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

	return uniqueSorted(slices.Collect(maps.Keys(suites))),
		uniqueSorted(slices.Collect(maps.Keys(testOwners))),
		uniqueSorted(slices.Collect(maps.Keys(suiteOwners))),
		nil
}

func queryBranchWorkflowSuiteFailures(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
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
					"must": buildTestCaseFailureMust(window, repo, params.Events, params.TestStatus),
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
			links, testOwners, suiteOwners, _ := extractBucketDetails(bucket, params.MaxLinks)
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
	params *Params,
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
					"must": buildTestCaseFailureMust(
						window,
						repo,
						params.Events,
						params.TestStatus,
						buildTermFilter("head_branch.keyword", branch),
					),
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
			links, testOwners, suiteOwners, _ := extractBucketDetails(bucket, params.MaxLinks)

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
	params *Params,
	repo string,
	window reportWindow,
) ([]reportGroup, error) {
	return queryFailureGroupsWithMust(
		ctx,
		logger,
		client,
		params,
		buildTestCaseFailureMust(window, repo, params.Events, params.TestStatus),
		true,
	)
}

func queryFailureGroupsForBranch(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	repo string,
	window reportWindow,
	branch string,
) ([]reportGroup, error) {
	return queryFailureGroupsWithMust(
		ctx,
		logger,
		client,
		params,
		buildTestCaseFailureMust(
			window,
			repo,
			params.Events,
			params.TestStatus,
			buildTermFilter("head_branch.keyword", branch),
		),
		false,
	)
}

func queryFailureGroupsWithMust(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	params *Params,
	must []any,
	includeDetails bool,
) ([]reportGroup, error) {
	groups := map[string]*reportGroup{}
	var afterKey map[string]any

	for {
		failuresAgg := map[string]any{
			"composite": map[string]any{
				"size": 1000,
				"sources": []any{
					map[string]any{"workflow": map[string]any{"terms": map[string]any{"field": "workflow_name.keyword"}}},
					map[string]any{"test_case": map[string]any{"terms": map[string]any{"field": "test_case_name.keyword"}}},
					map[string]any{"message": map[string]any{"terms": map[string]any{"field": "test_case_failure_message.keyword"}}},
				},
			},
		}
		if includeDetails {
			failuresAgg["aggs"] = map[string]any{"sample": buildTopHitsAgg(params.MaxLinks)}
		}

		query := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": must,
				},
			},
			"aggs": map[string]any{
				"failures": failuresAgg,
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

			if includeDetails {
				links, owners, suiteOwners, _ := extractBucketDetails(bucket, params.MaxLinks)
				group.Links = mergeLinks(group.Links, links, params.MaxLinks)
				group.TestCaseOwners = mergeStrings(group.TestCaseOwners, owners)
				group.TestSuiteOwners = mergeStrings(group.TestSuiteOwners, suiteOwners)
			}
		}

		afterKey, _ = agg["after_key"].(map[string]any)
		if afterKey == nil {
			break
		}
	}

	results := make([]reportGroup, 0, len(groups))
	for _, group := range groups {
		if includeDetails {
			group.TestCaseOwners = uniqueSorted(group.TestCaseOwners)
			group.TestSuiteOwners = uniqueSorted(group.TestSuiteOwners)
		}
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

// Markdown helpers

func renderLinks(links []reportLink) string {
	if len(links) == 0 {
		return ""
	}
	entries := make([]string, 0, len(links))
	for _, link := range links {
		parts := make([]string, 0, 2)
		if link.Workflow != "" {
			label := runLinkLabel
			runID := link.RunID
			if runID == 0 {
				runID = parseRunID(link.Workflow)
			}
			if runID > 0 {
				label = fmt.Sprintf(runLinkFmt, runID)
			} else if link.RunNumber > 0 {
				label = fmt.Sprintf(runLinkFmt, link.RunNumber)
			}
			parts = append(parts, fmt.Sprintf(markdownLinkFmt, label, link.Workflow))
		}
		if link.Job != "" {
			parts = append(parts, fmt.Sprintf(markdownLinkFmt, jobLinkLabel, link.Job))
		}
		if len(parts) > 0 {
			entries = append(entries, strings.Join(parts, linkPartsSep))
		}
	}
	return strings.Join(entries, linkEntriesSep)
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

func buildWorkflowRunMust(window reportWindow, repo string, events []string, extra ...any) []any {
	must := []any{
		buildRangeFilter(window.Since, window.Until),
		buildTypeFilter("workflow_run"),
		buildRepoTermFilter(repo),
		buildEventTermsFilter(events),
	}
	return append(must, extra...)
}

func buildTestCaseFailureMust(window reportWindow, repo string, events, testStatus []string, extra ...any) []any {
	must := []any{
		buildRangeFilter(window.Since, window.Until),
		buildTypeFilter("test_case"),
		buildRepoTermFilter(repo),
		buildEventTermsFilter(events),
		buildTermsFilter("test_case_status", testStatus),
	}
	return append(must, extra...)
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

func asInt(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return 0
	}
}

func asInt64(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	default:
		return 0
	}
}

func getIntFromMap(m map[string]any, key string) int {
	return asInt(m[key])
}

func getInt64FromMap(m map[string]any, key string) int64 {
	return asInt64(m[key])
}

func getInt(bucket map[string]any, key string) int {
	return asInt(bucket[key])
}

func getInt64(bucket map[string]any, key string) int64 {
	return asInt64(bucket[key])
}

func getMap(bucket map[string]any, key string) map[string]any {
	if val, ok := bucket[key].(map[string]any); ok {
		return val
	}
	return map[string]any{}
}

func extractBucketDetails(bucket map[string]any, maxLinks int) ([]reportLink, []string, []string, []string) {
	hits := extractTopHits(bucket)
	links := extractLinksFromHits(hits, maxLinks)
	owners, suiteOwners, suites := extractOwnersFromHits(hits)
	return links, owners, suiteOwners, suites
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
	return slices.Concat(existing, incoming)
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
	slug = slugifyRegex.ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return unknownSlug
	}
	return slug
}

func parseRunID(link string) int64 {
	matches := runIDRegex.FindStringSubmatch(link)
	if len(matches) < 2 {
		return 0
	}
	value, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func reportOutputPath(outputDir, component string) string {
	return filepath.Join(outputDir, component, readmeFileName)
}

func branchReportOutputPath(outputDir, component, branch string) string {
	return filepath.Join(outputDir, component, branchDirName, slugify(branch), readmeFileName)
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

func buildOtherBranchLinks(results []branchResult) []branchLink {
	if len(results) == 0 {
		return nil
	}
	sorted := append([]branchResult(nil), results...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Branch < sorted[j].Branch
	})
	links := make([]branchLink, 0, len(sorted))
	for _, branch := range sorted {
		failedRuns, runs := summarizeFailureRate(branch.Graphs.TotalSeries)
		links = append(links, branchLink{
			Name:           branch.Branch,
			Path:           filepath.ToSlash(filepath.Join(branchDirName, slugify(branch.Branch))) + "/",
			FailureSummary: formatFailureSummary(failedRuns, runs),
		})
	}
	return links
}

func summarizeFailureRate(points []dayPoint) (int, int) {
	totalRuns := 0
	totalFailures := 0
	for _, point := range points {
		totalRuns += point.TotalRuns
		totalFailures += point.TotalFailures
	}
	return totalFailures, totalRuns
}

func formatFailureSummary(failures, totalRuns int) string {
	percent := 0.0
	if totalRuns > 0 {
		percent = (float64(failures) / float64(totalRuns)) * 100
	}
	return fmt.Sprintf("%d / %d (%.1f%%)", failures, totalRuns, percent)
}

func isMainBranch(branch string) bool {
	return strings.HasPrefix(branch, mainBranchPrefix)
}
