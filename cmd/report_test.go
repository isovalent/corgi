package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNormalizeFailureMessage(t *testing.T) {
	input := "2025-02-18T12:34:56Z failed on 10.1.2.3 run 123456 uuid 123e4567-e89b-12d3-a456-426614174000 code 0xDEADBEEF"
	got := normalizeFailureMessage(input)
	if got == input {
		t.Fatalf("expected normalization to change input, got %q", got)
	}
	if want := "<ts> failed on <ip> run <num> uuid <uuid> code <hex>"; got != want {
		t.Fatalf("unexpected normalization: want %q got %q", want, got)
	}
}

func TestNormalizeFailureMessageCollapsesWhitespace(t *testing.T) {
	input := "error   at\n  line\t42"
	got := normalizeFailureMessage(input)
	if want := "error at line 42"; got != want {
		t.Fatalf("unexpected normalization: want %q got %q", want, got)
	}
}

func TestBuildEventTermsFilter(t *testing.T) {
	events := []string{"schedule", "push"}
	filter := buildEventTermsFilter(events)
	got, ok := filter["terms"].(map[string]any)
	if !ok {
		t.Fatalf("expected terms filter, got %T", filter["terms"])
	}
	values, ok := got["event.keyword"].([]string)
	if !ok {
		t.Fatalf("expected event.keyword string slice, got %T", got["event.keyword"])
	}
	if !reflect.DeepEqual(values, events) {
		t.Fatalf("unexpected events: want %v got %v", events, values)
	}
}

func TestBuildRepoTermFilter(t *testing.T) {
	filter := buildRepoTermFilter("cilium/cilium")
	terms, ok := filter["term"].(map[string]any)
	if !ok {
		t.Fatalf("expected term filter, got %T", filter["term"])
	}
	if terms["repository.full_name.keyword"] != "cilium/cilium" {
		t.Fatalf("unexpected repo value: %v", terms["repository.full_name.keyword"])
	}
}

func TestBuildReportWindowsIncludes60(t *testing.T) {
	now := time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC)
	windows := buildReportWindows(now, []int{7, 14, 30, 60, 90})
	if len(windows) != 5 {
		t.Fatalf("expected 5 windows, got %d", len(windows))
	}
	if windows[3].Days != 60 {
		t.Fatalf("expected 60-day window at index 3, got %d", windows[3].Days)
	}
}

func TestFormatFailureStat(t *testing.T) {
	got := formatFailureStat(3, 10)
	if got != "3/10 (30.0%)" {
		t.Fatalf("unexpected failure stat: %q", got)
	}

	got = formatFailureStat(2, 0)
	if got != "2/0 (0.0%)" {
		t.Fatalf("unexpected failure stat with zero runs: %q", got)
	}
}

func TestRenderLinksUsesRunNumber(t *testing.T) {
	links := []reportLink{{Workflow: "https://github.com/cilium/cilium/actions/runs/22174599299"}}
	out := renderLinks(links)
	expected := "[run#22174599299](https://github.com/cilium/cilium/actions/runs/22174599299)"
	if out != expected {
		t.Fatalf("unexpected markdown links output: got %q want %q", out, expected)
	}
}

func TestRenderLinksCommaSeparated(t *testing.T) {
	links := []reportLink{
		{Workflow: "https://github.com/cilium/cilium/actions/runs/1"},
		{Workflow: "https://github.com/cilium/cilium/actions/runs/2"},
	}
	out := renderLinks(links)
	expected := "[run#1](https://github.com/cilium/cilium/actions/runs/1), [run#2](https://github.com/cilium/cilium/actions/runs/2)"
	if out != expected {
		t.Fatalf("unexpected markdown links output: got %q want %q", out, expected)
	}
}

func TestParseRunID(t *testing.T) {
	id := parseRunID("https://github.com/cilium/cilium/actions/runs/22174599299")
	if id != 22174599299 {
		t.Fatalf("unexpected run id: %d", id)
	}
}

func TestComponentFromRepo(t *testing.T) {
	component := componentFromRepo("cilium/cilium")
	if component != "cilium" {
		t.Fatalf("unexpected component: %s", component)
	}
	component = componentFromRepo("cilium/tetragon")
	if component != "tetragon" {
		t.Fatalf("unexpected component: %s", component)
	}
}

func TestReportOutputPath(t *testing.T) {
	path := reportOutputPath("/tmp/output", "cilium")
	if path != "/tmp/output/cilium/README.md" {
		t.Fatalf("unexpected path: %s", path)
	}
}

func TestBranchReportOutputPath(t *testing.T) {
	path := branchReportOutputPath("/tmp/output", "tetragon", "feature/foo")
	if path != "/tmp/output/tetragon/branch/feature-foo/README.md" {
		t.Fatalf("unexpected path: %s", path)
	}
}

func TestFilterBranchesByPrefix(t *testing.T) {
	mainBranches, otherBranches := filterBranchesByPrefix(
		[]string{"main", "release-1.0", "mainline", "feature/foo"},
	)
	if !reflect.DeepEqual(mainBranches, []string{"main", "mainline"}) {
		t.Fatalf("unexpected main branches: %v", mainBranches)
	}
	if !reflect.DeepEqual(otherBranches, []string{"feature/foo", "release-1.0"}) {
		t.Fatalf("unexpected other branches: %v", otherBranches)
	}
}

func TestBuildOtherBranchLinks(t *testing.T) {
	links := buildOtherBranchLinks("cilium", []string{"release-1.0", "feature/foo"})
	if len(links) != 2 {
		t.Fatalf("unexpected link count: %d", len(links))
	}
	if links[0].Name != "feature/foo" || links[0].Path != "branch/feature-foo/" {
		t.Fatalf("unexpected first link: %+v", links[0])
	}
	if links[1].Name != "release-1.0" || links[1].Path != "branch/release-1-0/" {
		t.Fatalf("unexpected second link: %+v", links[1])
	}
}

func TestRenderLandingPageWritesReadme(t *testing.T) {
	outputDir := t.TempDir()
	if err := renderLandingPage(outputDir, []landingLink{
		{Title: "Cilium", File: "cilium/"},
	}); err != nil {
		t.Fatalf("render landing page: %v", err)
	}

	readmePath := filepath.Join(outputDir, "README.md")
	if _, err := os.Stat(readmePath); err != nil {
		t.Fatalf("expected README.md to exist: %v", err)
	}
	homePath := filepath.Join(outputDir, "Home.md")
	if _, err := os.Stat(homePath); !os.IsNotExist(err) {
		t.Fatalf("expected Home.md not to exist")
	}
}

func TestReportTemplateIncludesGraphLayout(t *testing.T) {
	data := reportTemplateData{
		Spec: reportSpec{
			Title:     "Test Report",
			Slug:      "Test-Report",
			Component: "test",
		},
		Generated:     "now",
		ExecutionTime: "1s",
		Results: []reportResult{
			{
				Window: reportWindow{Days: 7},
				BranchFailureGroupsByWorkflow: []branchResult{
					{Branch: "main"},
				},
			},
		},
	}

	var out bytes.Buffer
	if err := reportTemplate.Execute(&out, data); err != nil {
		t.Fatalf("render report template: %v", err)
	}

	rendered := out.String()
	if !strings.Contains(rendered, "class=\"graph-grid\"") {
		t.Fatalf("expected graph grid markup in report template output")
	}
	if !strings.Contains(rendered, "graph-modal") {
		t.Fatalf("expected graph modal markup in report template output")
	}
	if !strings.Contains(rendered, "graph-link") {
		t.Fatalf("expected graph link markup in report template output")
	}
}

func TestBranchTemplateIncludesGraphLayout(t *testing.T) {
	data := branchReportTemplateData{
		Spec: reportSpec{
			Title:     "Test Report",
			Slug:      "Test-Report",
			Component: "test",
		},
		Branch:        "main",
		Generated:     "now",
		ExecutionTime: "1s",
		Results: []branchWindowResult{
			{
				Window: reportWindow{Days: 7},
				Result: branchResult{Branch: "main"},
			},
		},
	}

	var out bytes.Buffer
	if err := branchTemplate.Execute(&out, data); err != nil {
		t.Fatalf("render branch template: %v", err)
	}

	rendered := out.String()
	if !strings.Contains(rendered, "class=\"graph-grid\"") {
		t.Fatalf("expected graph grid markup in branch template output")
	}
	if !strings.Contains(rendered, "graph-modal") {
		t.Fatalf("expected graph modal markup in branch template output")
	}
	if !strings.Contains(rendered, "graph-link") {
		t.Fatalf("expected graph link markup in branch template output")
	}
}

func TestReportTemplateEnablesMarkdownInDetailsTables(t *testing.T) {
	data := reportTemplateData{
		Spec: reportSpec{
			Title:     "Test Report",
			Slug:      "Test-Report",
			Component: "test",
		},
		Generated:     "now",
		ExecutionTime: "1s",
		Results: []reportResult{
			{
				Window: reportWindow{Days: 7},
				WorkflowFailures: []workflowCount{
					{Workflow: "wf", Count: 2, TotalRuns: 5},
				},
				BranchWorkflowSuiteFailures: []workflowSuiteCount{
					{Branch: "main", Workflow: "wf", TestSuite: "suite", Count: 1, TotalRuns: 5},
				},
			},
		},
	}

	var out bytes.Buffer
	if err := reportTemplate.Execute(&out, data); err != nil {
		t.Fatalf("render report template: %v", err)
	}

	rendered := out.String()
	if !strings.Contains(rendered, "<details markdown=\"1\"><summary>Table</summary>") {
		t.Fatalf("expected markdown-enabled details wrapper for report tables")
	}
	if !strings.Contains(rendered, "<div class=\"table-wrap\" markdown=\"1\">") {
		t.Fatalf("expected responsive table wrapper for report tables")
	}
	if !strings.Contains(rendered, ".table-wrap {") || !strings.Contains(rendered, "overflow-x: auto;") {
		t.Fatalf("expected responsive table CSS in report template output")
	}
	if !strings.Contains(rendered, "2/5 (40.0%)") {
		t.Fatalf("expected failure/runs stat in report template output")
	}
}

func TestBranchTemplateEnablesMarkdownInDetailsTables(t *testing.T) {
	data := branchReportTemplateData{
		Spec: reportSpec{
			Title:     "Test Report",
			Slug:      "Test-Report",
			Component: "test",
		},
		Branch:        "main",
		Generated:     "now",
		ExecutionTime: "1s",
		Results: []branchWindowResult{
			{
				Window: reportWindow{Days: 7},
				Result: branchResult{
					Branch: "main",
					WorkflowFailures: []workflowCount{
						{Workflow: "wf", Count: 2, TotalRuns: 5},
					},
					WorkflowSuiteFailures: []workflowSuiteFailureGroup{
						{Workflow: "wf", Count: 1, TotalRuns: 5},
					},
				},
			},
		},
	}

	var out bytes.Buffer
	if err := branchTemplate.Execute(&out, data); err != nil {
		t.Fatalf("render branch template: %v", err)
	}

	rendered := out.String()
	if !strings.Contains(rendered, "<details markdown=\"1\"><summary>Table</summary>") {
		t.Fatalf("expected markdown-enabled details wrapper for branch tables")
	}
	if !strings.Contains(rendered, "<div class=\"table-wrap\" markdown=\"1\">") {
		t.Fatalf("expected responsive table wrapper for branch tables")
	}
	if !strings.Contains(rendered, ".table-wrap {") || !strings.Contains(rendered, "overflow-x: auto;") {
		t.Fatalf("expected responsive table CSS in branch template output")
	}
	if !strings.Contains(rendered, "2/5 (40.0%)") {
		t.Fatalf("expected failure/runs stat in branch template output")
	}
}

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
