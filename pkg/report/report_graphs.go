package report

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/opensearch-project/opensearch-go"
)

var barChartSVGTemplate = template.Must(template.New("chart-bar.svg.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	barChartTemplatePath,
))

var lineChartSVGTemplate = template.Must(template.New("chart-lines.svg.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	lineChartTemplatePath,
))

var errorChartSVGTemplate = template.Must(template.New("chart-error.svg.tmpl").Funcs(reportTemplateFuncs()).ParseFS(
	reportTemplates,
	errorChartTemplatePath,
))

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
	params *Params,
	repo string,
	window reportWindow,
) (graphBundle, error) {
	series, err := queryDailyTotals(ctx, logger, client, params, repo, window)
	if err != nil {
		return graphBundle{}, err
	}

	topWorkflows, err := queryTopWorkflows(ctx, logger, client, params, repo, window, graphTopSeriesLimit)
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

	topBranches, err := queryTopBranchWorkflows(ctx, logger, client, params, repo, window, graphTopSeriesLimit)
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
	params *Params,
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
	params *Params,
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
	params *Params,
	repo string,
	window reportWindow,
	branch string,
) (graphBundle, error) {
	series, err := queryDailyTotalsForBranch(ctx, logger, client, params, repo, window, branch)
	if err != nil {
		return graphBundle{}, err
	}

	topWorkflows, err := queryTopWorkflowsForBranch(ctx, logger, client, params, repo, window, branch, graphTopSeriesLimit)
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
	params *Params,
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
	params *Params,
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
	params *Params,
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
	params *Params,
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
	params *Params,
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
	params *Params,
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
	params *Params,
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
	params *Params,
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
		renderTotalsChart(graphs.TotalSeries, chartTitleTotalFailures)); err != nil {
		return err
	}
	if err := writeSVG(filepath.Join(graphDir, fmt.Sprintf("%s-workflows.svg", prefix)),
		renderSeriesChart(graphs.WorkflowLines, chartTitleWorkflowFailures)); err != nil {
		return err
	}
	if len(graphs.BranchLines) > 0 {
		if err := writeSVG(filepath.Join(graphDir, fmt.Sprintf("%s-branches.svg", prefix)),
			renderSeriesChart(graphs.BranchLines, chartTitleBranchWorkflowFails)); err != nil {
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
	content := renderBarChart(chartTitleWorkflowRunFailures, toWorkflowBarSeries(bars), true)
	return writeSVG(path, content)
}

type barSeries struct {
	Label      string
	TotalRuns  int
	TotalFails int
}

type svgAxis struct {
	X0 int
	Y0 int
	X1 int
	Y1 int
}

type barChartSVGBar struct {
	X           float64
	Width       float64
	YRuns       float64
	RunsHeight  float64
	YFails      float64
	FailsHeight float64
	Label       string
	LabelY      int
}

type barChartSVGData struct {
	Width           int
	Height          int
	Title           string
	TitleX          int
	TitleY          int
	Axis            svgAxis
	BackgroundColor string
	AxisColor       string
	RunsColor       string
	RunsOpacity     float64
	FailsColor      string
	FailsOpacity    float64
	Bars            []barChartSVGBar
}

type lineChartXTick struct {
	X     int
	Label string
}

type lineChartYTick struct {
	Y      int
	LabelY int
	Label  int
}

type lineChartPath struct {
	Path    string
	Color   string
	LegendX int
	LegendY int
	Name    string
}

type lineChartArea struct {
	Name    string
	Path    string
	Color   string
	Opacity float64
}

type lineChartSVGData struct {
	Width           int
	Height          int
	Title           string
	TitleX          int
	TitleY          int
	Axis            svgAxis
	AxisLabelX      int
	AxisLabelY      int
	XTickMarkBottom int
	XTickMarkTop    int
	XTickLabelY     int
	YTickLabelX     int
	XTicks          []lineChartXTick
	YTicks          []lineChartYTick
	Areas           []lineChartArea
	SeriesPaths     []lineChartPath
	AxisLabel       string
	BackgroundColor string
	AxisColor       string
	XTickColor      string
	GridColor       string
}

type errorChartSVGData struct {
	Width           int
	Height          int
	BackgroundColor string
	Message         string
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

	data := barChartSVGData{
		Width:           width,
		Height:          height,
		Title:           title,
		TitleX:          padLeft,
		TitleY:          padTop - 30,
		BackgroundColor: graphColorBackground,
		AxisColor:       graphColorAxis,
		RunsColor:       graphColorRuns,
		RunsOpacity:     graphColorRunsOpacity,
		FailsColor:      graphColorFailures,
		FailsOpacity:    graphColorFailuresOpacity,
	}
	if len(series) == 0 {
		return renderSVGTemplate(barChartSVGTemplate, data)
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
	data.Axis = svgAxis{X0: x0, Y0: y0, X1: x1, Y1: y1}
	data.Bars = make([]barChartSVGBar, 0, len(series))

	for i, item := range series {
		x := float64(padLeft) + barWidth*float64(i) + barWidth*0.1
		widthPx := barWidth * 0.8
		runsHeight := (float64(item.TotalRuns) / float64(maxVal)) * plotHeight
		failsHeight := (float64(item.TotalFails) / float64(maxVal)) * plotHeight
		yRuns := float64(y0) - runsHeight
		yFails := float64(y0) - failsHeight

		label := item.Label
		labelY := y0 + 30
		data.Bars = append(data.Bars, barChartSVGBar{
			X:           x,
			Width:       widthPx,
			YRuns:       yRuns,
			RunsHeight:  runsHeight,
			YFails:      yFails,
			FailsHeight: failsHeight,
			Label:       label,
			LabelY:      labelY,
		})
	}

	return renderSVGTemplate(barChartSVGTemplate, data)
}

func renderTotalsChart(points []dayPoint, title string) string {
	chart := svgChart{Width: 900, Height: 320, Pad: 40}
	width := chart.Width
	height := chart.Height
	pad := chart.Pad
	titlePad := 26
	topPad := pad + titlePad + 8
	bottomPad := pad + 20
	leftPad := pad + 10
	rightPad := pad

	ordered := append([]dayPoint(nil), points...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].Date.Before(ordered[j].Date)
	})

	maxVal := 1.0
	minDate, maxDate := time.Time{}, time.Time{}
	for _, point := range ordered {
		runs := float64(point.TotalRuns)
		successfulRuns := float64(calcSuccessfulRuns(point))
		if runs > maxVal {
			maxVal = runs
		}
		if successfulRuns > maxVal {
			maxVal = successfulRuns
		}
		if minDate.IsZero() || point.Date.Before(minDate) {
			minDate = point.Date
		}
		if maxDate.IsZero() || point.Date.After(maxDate) {
			maxDate = point.Date
		}
	}

	if minDate.IsZero() || maxDate.IsZero() {
		minDate = time.Now().AddDate(0, 0, -1)
		maxDate = time.Now()
	}

	plotWidth := float64(width - leftPad - rightPad)
	plotHeight := float64(height - topPad - bottomPad)
	x0 := leftPad
	y0 := height - bottomPad
	x1 := width - rightPad
	y1 := topPad
	data := lineChartSVGData{
		Width:           width,
		Height:          height,
		Title:           title,
		TitleX:          leftPad,
		TitleY:          pad - 8,
		Axis:            svgAxis{X0: x0, Y0: y0, X1: x1, Y1: y1},
		AxisLabelX:      x0,
		AxisLabelY:      y1 - 8,
		XTickMarkBottom: y0,
		XTickMarkTop:    y0 + 4,
		XTickLabelY:     y0 + 18,
		YTickLabelX:     x0 - 6,
		AxisLabel:       chartLineAxisLabelRuns,
		BackgroundColor: graphColorBackground,
		AxisColor:       graphColorAxis,
		XTickColor:      graphColorTick,
		GridColor:       graphColorGrid,
	}

	totalDays := int(maxDate.Sub(minDate).Hours()/24) + 1
	stepDays := totalDays / 6
	if stepDays < 1 {
		stepDays = 1
	}
	data.XTicks = make([]lineChartXTick, 0, (totalDays/stepDays)+2)
	for day := 0; day <= totalDays; day += stepDays {
		tickDate := minDate.AddDate(0, 0, day)
		x := x0 + int(scaleTime(tickDate, minDate, maxDate, plotWidth))
		data.XTicks = append(data.XTicks, lineChartXTick{
			X:     x,
			Label: tickDate.Format(lineDateLabelFmt),
		})
	}

	yTicks := []float64{0, maxVal / 2, maxVal}
	data.YTicks = make([]lineChartYTick, 0, len(yTicks))
	for _, val := range yTicks {
		y := y0 - int(scaleValue(val, maxVal, plotHeight))
		data.YTicks = append(data.YTicks, lineChartYTick{
			Y:      y,
			LabelY: y + 4,
			Label:  int(val),
		})
	}

	runPoints := make([]svgPoint, 0, len(ordered))
	successPoints := make([]svgPoint, 0, len(ordered))
	for _, point := range ordered {
		x := leftPad + int(scaleTime(point.Date, minDate, maxDate, plotWidth))
		runY := topPad + int(plotHeight-scaleValue(float64(point.TotalRuns), maxVal, plotHeight))
		successY := topPad + int(plotHeight-scaleValue(float64(calcSuccessfulRuns(point)), maxVal, plotHeight))

		runPoints = append(runPoints, svgPoint{X: x, Y: runY})
		successPoints = append(successPoints, svgPoint{X: x, Y: successY})
	}

	if len(runPoints) > 0 {
		data.Areas = append(data.Areas, lineChartArea{
			Name:    "failure-gap",
			Path:    buildAreaPath(runPoints, successPoints),
			Color:   graphColorFailureGap,
			Opacity: graphColorFailureGapOpacity,
		})
		data.SeriesPaths = append(data.SeriesPaths,
			lineChartPath{
				Path:    buildLinePath(successPoints),
				Color:   graphColorSuccessfulRuns,
				LegendX: leftPad + 10,
				LegendY: topPad + 12,
				Name:    chartSeriesNameSuccessfulRuns,
			},
			lineChartPath{
				Path:    buildLinePath(runPoints),
				Color:   graphColorRunsTotal,
				LegendX: leftPad + 10,
				LegendY: topPad + 24,
				Name:    chartSeriesNameRuns,
			},
		)
	}

	return renderSVGTemplate(lineChartSVGTemplate, data)
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

	plotWidth := float64(width - leftPad - rightPad)
	plotHeight := float64(height - topPad - bottomPad)
	x0 := leftPad
	y0 := height - bottomPad
	x1 := width - rightPad
	y1 := topPad
	data := lineChartSVGData{
		Width:           width,
		Height:          height,
		Title:           title,
		TitleX:          leftPad,
		TitleY:          pad - 8,
		Axis:            svgAxis{X0: x0, Y0: y0, X1: x1, Y1: y1},
		AxisLabelX:      x0,
		AxisLabelY:      y1 - 8,
		XTickMarkBottom: y0,
		XTickMarkTop:    y0 + 4,
		XTickLabelY:     y0 + 18,
		YTickLabelX:     x0 - 6,
		AxisLabel:       chartLineAxisLabel,
		BackgroundColor: graphColorBackground,
		AxisColor:       graphColorAxis,
		XTickColor:      graphColorTick,
		GridColor:       graphColorGrid,
	}

	totalDays := int(maxDate.Sub(minDate).Hours()/24) + 1
	stepDays := totalDays / 6
	if stepDays < 1 {
		stepDays = 1
	}
	data.XTicks = make([]lineChartXTick, 0, (totalDays/stepDays)+2)
	for day := 0; day <= totalDays; day += stepDays {
		tickDate := minDate.AddDate(0, 0, day)
		x := x0 + int(scaleTime(tickDate, minDate, maxDate, plotWidth))
		data.XTicks = append(data.XTicks, lineChartXTick{
			X:     x,
			Label: tickDate.Format(lineDateLabelFmt),
		})
	}

	yTicks := []float64{0, maxVal / 2, maxVal}
	data.YTicks = make([]lineChartYTick, 0, len(yTicks))
	for _, val := range yTicks {
		y := y0 - int(scaleValue(val, maxVal, plotHeight))
		data.YTicks = append(data.YTicks, lineChartYTick{
			Y:      y,
			LabelY: y + 4,
			Label:  int(val),
		})
	}

	data.SeriesPaths = make([]lineChartPath, 0, len(lines))
	for i, line := range lines {
		if len(line.Points) == 0 {
			continue
		}
		color := lineSeriesColors[i%len(lineSeriesColors)]
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
		data.SeriesPaths = append(data.SeriesPaths, lineChartPath{
			Path:    path.String(),
			Color:   color,
			LegendX: leftPad + 10,
			LegendY: topPad + 12 + (i * 12),
			Name:    line.Name,
		})
	}

	return renderSVGTemplate(lineChartSVGTemplate, data)
}

type svgPoint struct {
	X int
	Y int
}

func calcSuccessfulRuns(point dayPoint) int {
	successfulRuns := point.TotalRuns - point.TotalFailures
	if successfulRuns < 0 {
		return 0
	}
	return successfulRuns
}

func buildLinePath(points []svgPoint) string {
	if len(points) == 0 {
		return ""
	}

	var path strings.Builder
	for i, point := range points {
		if i == 0 {
			path.WriteString(fmt.Sprintf("M %d %d", point.X, point.Y))
		} else {
			path.WriteString(fmt.Sprintf(" L %d %d", point.X, point.Y))
		}
	}

	return path.String()
}

func buildAreaPath(upperPoints, lowerPoints []svgPoint) string {
	if len(upperPoints) == 0 || len(upperPoints) != len(lowerPoints) {
		return ""
	}

	var path strings.Builder
	path.WriteString(fmt.Sprintf("M %d %d", upperPoints[0].X, upperPoints[0].Y))
	for i := 1; i < len(upperPoints); i++ {
		path.WriteString(fmt.Sprintf(" L %d %d", upperPoints[i].X, upperPoints[i].Y))
	}
	for i := len(lowerPoints) - 1; i >= 0; i-- {
		path.WriteString(fmt.Sprintf(" L %d %d", lowerPoints[i].X, lowerPoints[i].Y))
	}
	path.WriteString(" Z")

	return path.String()
}

func renderSVGTemplate(tmpl *template.Template, data any) string {
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		b.Reset()
		fallback := errorChartSVGData{
			Width:           errorChartWidth,
			Height:          errorChartHeight,
			BackgroundColor: graphColorBackground,
			Message:         err.Error(),
		}
		if fallbackErr := errorChartSVGTemplate.Execute(&b, fallback); fallbackErr != nil {
			return ""
		}
	}
	return b.String()
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
