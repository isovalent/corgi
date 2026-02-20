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

func TestBuildTrendsForWindowPrioritizesCurrentFailurePercentage(t *testing.T) {
	window := reportWindow{
		Since: time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC),
		Until: time.Date(2026, 2, 20, 0, 0, 0, 0, time.UTC),
		Days:  7,
	}

	groupCallCount := 0
	queryGroupsFn := func(w reportWindow) ([]reportGroup, error) {
		groupCallCount++
		switch groupCallCount {
		case 1:
			if !w.Since.Equal(window.Since) || !w.Until.Equal(window.Until) {
				t.Fatalf("unexpected current window: %+v", w)
			}
			return []reportGroup{
				{
					Key:            "stable-high",
					Workflow:       "wf-stable",
					TestCaseName:   "test-stable",
					FailureMessage: "msg-stable",
					Count:          100,
				},
				{
					Key:            "regressed",
					Workflow:       "wf-regressed",
					TestCaseName:   "test-regressed",
					FailureMessage: "msg-regressed",
					Count:          10,
				},
			}, nil
		case 2:
			expectedPrev := reportWindow{
				Since: window.Since.AddDate(0, 0, -window.Days),
				Until: window.Since,
				Days:  window.Days,
			}
			if !w.Since.Equal(expectedPrev.Since) || !w.Until.Equal(expectedPrev.Until) {
				t.Fatalf("unexpected previous window: %+v", w)
			}
			return []reportGroup{
				{
					Key:            "stable-high",
					Workflow:       "wf-stable",
					TestCaseName:   "test-stable",
					FailureMessage: "msg-stable",
					Count:          100,
				},
			}, nil
		default:
			t.Fatalf("group query called too many times: %d", groupCallCount)
			return nil, nil
		}
	}

	runTotalsCallCount := 0
	queryRunTotalsFn := func(w reportWindow) (map[string]int, error) {
		runTotalsCallCount++
		switch runTotalsCallCount {
		case 1:
			if !w.Since.Equal(window.Since) || !w.Until.Equal(window.Until) {
				t.Fatalf("unexpected current totals window: %+v", w)
			}
			return map[string]int{
				"wf-stable":    1000,
				"wf-regressed": 10,
			}, nil
		case 2:
			expectedPrev := reportWindow{
				Since: window.Since.AddDate(0, 0, -window.Days),
				Until: window.Since,
				Days:  window.Days,
			}
			if !w.Since.Equal(expectedPrev.Since) || !w.Until.Equal(expectedPrev.Until) {
				t.Fatalf("unexpected previous totals window: %+v", w)
			}
			return map[string]int{
				"wf-stable":    1000,
				"wf-regressed": 10,
			}, nil
		default:
			t.Fatalf("run totals query called too many times: %d", runTotalsCallCount)
			return nil, nil
		}
	}

	trends, err := buildTrendsForWindow(10, window, queryGroupsFn, queryRunTotalsFn)
	if err != nil {
		t.Fatalf("build trends: %v", err)
	}
	if len(trends) != 2 {
		t.Fatalf("unexpected trend count: got %d want 2", len(trends))
	}
	if trends[0].Workflow != "wf-regressed" {
		t.Fatalf("expected wf-regressed first, got %q", trends[0].Workflow)
	}
	if trends[1].Workflow != "wf-stable" {
		t.Fatalf("expected wf-stable second, got %q", trends[1].Workflow)
	}
	if trends[0].CurrentTotalRuns != 10 || trends[0].PreviousTotalRuns != 10 {
		t.Fatalf("unexpected run totals for wf-regressed trend: %+v", trends[0])
	}
}

func TestRenderLinks(t *testing.T) {
	tests := []struct {
		name  string
		links []reportLink
		want  string
	}{
		{
			name:  "run id from workflow url",
			links: []reportLink{{Workflow: "https://github.com/cilium/cilium/actions/runs/22174599299"}},
			want:  "[run#22174599299](https://github.com/cilium/cilium/actions/runs/22174599299)",
		},
		{
			name: "comma separated runs",
			links: []reportLink{
				{Workflow: "https://github.com/cilium/cilium/actions/runs/1"},
				{Workflow: "https://github.com/cilium/cilium/actions/runs/2"},
			},
			want: "[run#1](https://github.com/cilium/cilium/actions/runs/1), [run#2](https://github.com/cilium/cilium/actions/runs/2)",
		},
		{
			name:  "run and job",
			links: []reportLink{{Workflow: "https://github.com/cilium/cilium/actions/runs/3", Job: "https://github.com/cilium/cilium/actions/jobs/9"}},
			want:  "[run#3](https://github.com/cilium/cilium/actions/runs/3) / [job](https://github.com/cilium/cilium/actions/jobs/9)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renderLinks(tt.links); got != tt.want {
				t.Fatalf("unexpected markdown links output: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestReportPaths(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "report",
			got:  reportOutputPath("/tmp/output", "cilium"),
			want: "/tmp/output/cilium/README.md",
		},
		{
			name: "branch report",
			got:  branchReportOutputPath("/tmp/output", "tetragon", "feature/foo"),
			want: "/tmp/output/tetragon/branch/feature-foo/README.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("unexpected path: got %q want %q", tt.got, tt.want)
			}
		})
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
	links := buildOtherBranchLinks([]branchResult{
		{
			Branch: "release-1.0",
			Graphs: graphBundle{
				TotalSeries: []dayPoint{
					{TotalRuns: 4, TotalFailures: 1},
					{TotalRuns: 6, TotalFailures: 2},
				},
			},
		},
		{
			Branch: "feature/foo",
			Graphs: graphBundle{
				TotalSeries: []dayPoint{
					{TotalRuns: 5, TotalFailures: 1},
				},
			},
		},
	})
	if len(links) != 2 {
		t.Fatalf("unexpected link count: %d", len(links))
	}
	if links[0].Name != "feature/foo" || links[0].Path != "branch/feature-foo/" || links[0].FailureSummary != "1 / 5 (20.0%)" {
		t.Fatalf("unexpected first link: %+v", links[0])
	}
	if links[1].Name != "release-1.0" || links[1].Path != "branch/release-1-0/" || links[1].FailureSummary != "3 / 10 (30.0%)" {
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

func TestWriteReportCSSWritesFile(t *testing.T) {
	outputDir := t.TempDir()
	if err := writeReportCSS(outputDir); err != nil {
		t.Fatalf("write report css: %v", err)
	}

	cssPath := filepath.Join(outputDir, reportCSSName)
	content, err := os.ReadFile(cssPath)
	if err != nil {
		t.Fatalf("read report css: %v", err)
	}

	rendered := string(content)
	if !strings.Contains(rendered, ".table-wrap") {
		t.Fatalf("expected table styles in external css")
	}
	if !strings.Contains(rendered, ".right") {
		t.Fatalf("expected shared branch styles in external css")
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
	if !strings.Contains(rendered, `<a href="graphs/Test-Report-7d-total.svg" target="_blank" rel="noopener noreferrer"><img src="graphs/Test-Report-7d-total.svg" alt="Total failures vs runs"/></a>`) {
		t.Fatalf("expected clickable total graph image that opens in new tab")
	}
	if !strings.Contains(rendered, `<a href="graphs/Test-Report-7d-workflow-bars.svg" target="_blank" rel="noopener noreferrer"><img src="graphs/Test-Report-7d-workflow-bars.svg" alt="Workflow runs vs failures"/></a>`) {
		t.Fatalf("expected clickable workflow bar chart image that opens in new tab")
	}
}

func TestReportTemplateRendersTrendPercentagesWithFailedCounts(t *testing.T) {
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
				Trends: []trendItem{
					{
						Status:            "🔴",
						Workflow:          "wf",
						Label:             "`tc` `msg`",
						Previous:          2,
						PreviousTotalRuns: 5,
						Current:           3,
						CurrentTotalRuns:  5,
					},
				},
			},
		},
	}

	var out bytes.Buffer
	if err := reportTemplate.Execute(&out, data); err != nil {
		t.Fatalf("render report template: %v", err)
	}

	rendered := out.String()
	if !strings.Contains(rendered, "40.0%(2/5) -> 60.0%(3/5)") {
		t.Fatalf("expected trend output to include percentages and counts, got:\n%s", rendered)
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
	if !strings.Contains(rendered, `<a href="graphs/Test-Report-7d-main-total.svg" target="_blank" rel="noopener noreferrer"><img src="graphs/Test-Report-7d-main-total.svg" alt="Total failures vs runs"/></a>`) {
		t.Fatalf("expected clickable total graph image that opens in new tab")
	}
	if !strings.Contains(rendered, `<a href="graphs/Test-Report-7d-main-workflow-bars.svg" target="_blank" rel="noopener noreferrer"><img src="graphs/Test-Report-7d-main-workflow-bars.svg" alt="Workflow runs vs failures"/></a>`) {
		t.Fatalf("expected clickable workflow bar chart image that opens in new tab")
	}
}

func TestBranchTemplateRendersTrendPercentagesWithFailedCounts(t *testing.T) {
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
					Trends: []trendItem{
						{
							Status:            "🔴",
							Workflow:          "wf",
							Label:             "`tc` `msg`",
							Previous:          2,
							PreviousTotalRuns: 5,
							Current:           3,
							CurrentTotalRuns:  5,
						},
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
	if !strings.Contains(rendered, "40.0%(2/5) -> 60.0%(3/5)") {
		t.Fatalf("expected trend output to include percentages and counts, got:\n%s", rendered)
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
	if !strings.Contains(rendered, "<link rel=\"stylesheet\" href=\"report.css\"/>") {
		t.Fatalf("expected external stylesheet reference in report template output")
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
	if !strings.Contains(rendered, "<link rel=\"stylesheet\" href=\"../../report.css\"/>") {
		t.Fatalf("expected external stylesheet reference in branch template output")
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
					{Name: "v1.19", Path: "branch/v1-19/", FailureSummary: "1 / 2 (50.0%)"},
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
	const listItem = "- [v1.19](branch/v1-19/): 1 / 2 (50.0%)"
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
