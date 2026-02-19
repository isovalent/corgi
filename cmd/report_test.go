package cmd

import (
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

func TestRenderLinksUsesRunNumber(t *testing.T) {
	links := []reportLink{{Workflow: "https://github.com/cilium/cilium/actions/runs/22174599299"}}
	out := renderLinks(links)
	if !strings.Contains(out, "run#22174599299") {
		t.Fatalf("expected run number label, got %q", out)
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
	if path != "/tmp/output/cilium/report.md" {
		t.Fatalf("unexpected path: %s", path)
	}
}

func TestBranchReportOutputPath(t *testing.T) {
	path := branchReportOutputPath("/tmp/output", "tetragon", "feature/foo")
	if path != "/tmp/output/tetragon/branch/feature-foo/report.md" {
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
	if links[0].Name != "feature/foo" || links[0].Path != "branch/feature-foo/report.md" {
		t.Fatalf("unexpected first link: %+v", links[0])
	}
	if links[1].Name != "release-1.0" || links[1].Path != "branch/release-1-0/report.md" {
		t.Fatalf("unexpected second link: %+v", links[1])
	}
}
