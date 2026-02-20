package cmd

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
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
