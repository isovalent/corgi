package report

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
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
	if !strings.Contains(rendered, "### Graphs (all branches,") {
		t.Fatalf("expected graphs section heading in report template output")
	}
	if !strings.Contains(rendered, "![Total failures vs runs](graphs/") {
		t.Fatalf("expected total graph markdown image in report template output")
	}
	if !strings.Contains(rendered, "![Workflow runs vs failures](graphs/") {
		t.Fatalf("expected workflow bar chart markdown image in report template output")
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
	if !strings.Contains(rendered, "#### Graphs (branch") {
		t.Fatalf("expected graphs section heading in branch template output")
	}
	if !strings.Contains(rendered, "![Total failures vs runs](graphs/") {
		t.Fatalf("expected total graph markdown image in branch template output")
	}
	if !strings.Contains(rendered, "![Workflow runs vs failures](graphs/") {
		t.Fatalf("expected workflow bar chart markdown image in branch template output")
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

func TestReportTemplateConditionallyRendersBranchSection(t *testing.T) {
	makeData := func(otherBranches []branchLink) reportTemplateData {
		return reportTemplateData{
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
					BranchWorkflowSuiteFailures: []workflowSuiteCount{
						{Branch: "main", Workflow: "wf", TestSuite: "suite", Count: 1, TotalRuns: 5},
					},
					OtherBranches: otherBranches,
				},
			},
		}
	}

	t.Run("hidden when only main branches", func(t *testing.T) {
		var out bytes.Buffer
		if err := reportTemplate.Execute(&out, makeData(nil)); err != nil {
			t.Fatalf("render report template: %v", err)
		}

		rendered := out.String()
		if strings.Contains(rendered, "### Per workflow+branch+test CI failures") {
			t.Fatalf("expected branch section to be omitted when no non-main branches exist")
		}
	})

	t.Run("shown when non-main branches exist", func(t *testing.T) {
		var out bytes.Buffer
		if err := reportTemplate.Execute(&out, makeData([]branchLink{
			{Name: "release-1.16", Path: "branch/release-1-16/"},
		})); err != nil {
			t.Fatalf("render report template: %v", err)
		}

		rendered := out.String()
		if !strings.Contains(rendered, "### Per workflow+branch+test CI failures") {
			t.Fatalf("expected branch section when non-main branches exist")
		}
	})
}

func TestReportTemplateSeparatesOtherBranchesListFromNextWindow(t *testing.T) {
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
				Window: reportWindow{
					Days:  7,
					Since: time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC),
					Until: time.Date(2026, 2, 20, 0, 0, 0, 0, time.UTC),
				},
				OtherBranches: []branchLink{
					{Name: "v1.19", Path: "branch/v1-19/"},
				},
			},
			{
				Window: reportWindow{
					Days:  14,
					Since: time.Date(2026, 2, 6, 0, 0, 0, 0, time.UTC),
					Until: time.Date(2026, 2, 20, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	}

	var out bytes.Buffer
	if err := reportTemplate.Execute(&out, data); err != nil {
		t.Fatalf("render report template: %v", err)
	}

	rendered := out.String()
	const listItem = "- [v1.19](branch/v1-19/)"
	const nextHeading = "## Last 14 days (2026-02-06 to 2026-02-20)"
	listIdx := strings.Index(rendered, listItem)
	if listIdx == -1 {
		t.Fatalf("expected other branches list item in rendered output")
	}
	headingIdx := strings.Index(rendered, nextHeading)
	if headingIdx == -1 {
		t.Fatalf("expected next window heading in rendered output")
	}
	if headingIdx <= listIdx {
		t.Fatalf("expected next window heading after branch list")
	}
	between := rendered[listIdx+len(listItem) : headingIdx]
	if !strings.Contains(between, "\n\n") {
		t.Fatalf("expected blank line between branch list and next window heading")
	}
}
