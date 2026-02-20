package report

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"
)

func TestRenderBarChartDoesNotTruncateLabels(t *testing.T) {
	label := "very-long-workflow-name-that-should-not-truncate"
	series := []barSeries{
		{Label: label, TotalRuns: 10, TotalFails: 2},
	}
	svg := renderBarChart("title", series, true)
	if !strings.Contains(svg, label) {
		t.Fatalf("expected full label in svg output")
	}
	if strings.Contains(svg, "…") {
		t.Fatalf("expected no ellipsis in svg output")
	}
}

func TestRenderBarChartAllocatesSpaceForLongLabels(t *testing.T) {
	shortSeries := []barSeries{{Label: "short", TotalRuns: 10, TotalFails: 2}}
	longSeries := []barSeries{{
		Label:      "workflow-name-that-is-significantly-longer-than-normal-and-should-fit",
		TotalRuns:  10,
		TotalFails: 2,
	}}

	shortSVG := renderBarChart("title", shortSeries, true)
	longSVG := renderBarChart("title", longSeries, true)

	_, shortH := mustSVGDimensions(t, shortSVG)
	_, longH := mustSVGDimensions(t, longSVG)
	if longH <= shortH {
		t.Fatalf("expected taller chart for long labels, got short=%d long=%d", shortH, longH)
	}
}

func TestRenderBarChartUsesTemplateMarkup(t *testing.T) {
	series := []barSeries{{Label: "wf", TotalRuns: 4, TotalFails: 1}}
	svg := renderBarChart("title", series, true)
	if !strings.Contains(svg, `data-chart="bar"`) {
		t.Fatalf("expected bar chart template marker in svg output")
	}
}

func TestRenderBarChartIncludesYAxisNumbers(t *testing.T) {
	series := []barSeries{
		{Label: "wf-a", TotalRuns: 12, TotalFails: 3},
		{Label: "wf-b", TotalRuns: 6, TotalFails: 1},
	}

	svg := renderBarChart("title", series, true)
	if !strings.Contains(svg, `text-anchor="end">0</text>`) {
		t.Fatalf("expected y-axis zero label in bar chart output")
	}
	if !strings.Contains(svg, `text-anchor="end">12</text>`) {
		t.Fatalf("expected y-axis max label in bar chart output")
	}
}

func TestRenderSeriesChartUsesTemplateMarkup(t *testing.T) {
	lines := []seriesLine{
		{
			Name: "wf",
			Points: []dayPoint{
				{Date: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), TotalFailures: 1},
				{Date: time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC), TotalFailures: 2},
			},
		},
	}
	svg := renderSeriesChart(lines, "Failures per workflow")
	if !strings.Contains(svg, `data-chart="line"`) {
		t.Fatalf("expected line chart template marker in svg output")
	}
}

func TestRenderTotalsChartUsesSuccessfulRunsAndFailureGap(t *testing.T) {
	points := []dayPoint{
		{
			Date:          time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			TotalRuns:     10,
			TotalFailures: 3,
		},
		{
			Date:          time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC),
			TotalRuns:     12,
			TotalFailures: 2,
		},
	}
	svg := renderTotalsChart(points, chartTitleTotalFailures)

	if !strings.Contains(svg, `data-chart="line"`) {
		t.Fatalf("expected line chart template marker in totals chart output")
	}
	if !strings.Contains(svg, "Successful runs") {
		t.Fatalf("expected successful runs legend label in totals chart output")
	}
	if !strings.Contains(svg, ">Runs</text>") {
		t.Fatalf("expected runs legend label in totals chart output")
	}
	if !strings.Contains(svg, `stroke="#16a34a"`) {
		t.Fatalf("expected successful runs line color in totals chart output")
	}
	if !strings.Contains(svg, `stroke="#111827"`) {
		t.Fatalf("expected runs line color in totals chart output")
	}
	if !strings.Contains(svg, `data-area="failure-gap"`) {
		t.Fatalf("expected failure gap area marker in totals chart output")
	}
	if !strings.Contains(svg, `fill="#ef4444"`) {
		t.Fatalf("expected failure gap fill color in totals chart output")
	}
	if !strings.Contains(svg, `data-area="successful-runs-area"`) {
		t.Fatalf("expected successful runs area marker in totals chart output")
	}
	if !strings.Contains(svg, `fill="#16a34a"`) {
		t.Fatalf("expected successful runs area fill color in totals chart output")
	}
	if !strings.Contains(svg, `fill-opacity="0.2"`) {
		t.Fatalf("expected successful runs area opacity in totals chart output")
	}
}

func TestRenderSVGTemplateUsesErrorTemplateFallback(t *testing.T) {
	broken := template.Must(template.New("broken").Parse(`{{ index . 0 }}`))
	svg := renderSVGTemplate(broken, 42)

	if !strings.Contains(svg, `data-chart="error"`) {
		t.Fatalf("expected error chart template marker in fallback svg output")
	}
	if !strings.Contains(svg, "error calling index:") || !strings.Contains(svg, "index item of type int") {
		t.Fatalf("expected template execution error message in fallback output")
	}
}

func mustSVGDimensions(t *testing.T, svg string) (int, int) {
	t.Helper()
	re := regexp.MustCompile(`width="([0-9]+)" height="([0-9]+)"`)
	m := re.FindStringSubmatch(svg)
	if len(m) != 3 {
		t.Fatalf("failed to parse svg dimensions from %q", svg)
	}
	w, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse width: %v", err)
	}
	h, err := strconv.Atoi(m[2])
	if err != nil {
		t.Fatalf("parse height: %v", err)
	}
	return w, h
}
