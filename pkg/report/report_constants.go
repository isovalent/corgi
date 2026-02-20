package report

import "regexp"

const (
	templateReportPath  = "templates/report.md.tmpl"
	templateLandingPath = "templates/landing.md.tmpl"
	templateBranchPath  = "templates/branch.md.tmpl"
	templateReportCSS   = "templates/report.css.tmpl"

	barChartTemplatePath   = "templates/chart-bar.svg.tmpl"
	lineChartTemplatePath  = "templates/chart-lines.svg.tmpl"
	errorChartTemplatePath = "templates/chart-error.svg.tmpl"

	defaultRunsIndex        = "runs-oss"
	defaultTop              = 50
	defaultMaxLinks         = 5
	defaultTrendOrangeRange = 2.5

	repoCilium   = "cilium/cilium"
	repoTetragon = "cilium/tetragon"
	compCilium   = "cilium"
	compTetragon = "tetragon"

	reportTitleCilium   = "Cilium OSS: CI health report"
	reportSlugCilium    = "Cilium-OSS-CI-health-report"
	reportTitleTetragon = "Tetragon OSS: CI health report"
	reportSlugTetragon  = "Tetragon-OSS-CI-health-report"

	windowDateLayout = "2006-01-02"
	windowTitleFmt   = "Last %d days (%s to %s)"
	windowTagFmt     = "last %d days"

	failureRateFmt = "Failures: %d / %d (%.1f%%)"
	failureStatFmt = "%d/%d (%.1f%%)"

	readmeFileName   = "README.md"
	reportCSSName    = "report.css"
	branchDirName    = "branch"
	mainBranchPrefix = "main"
	unknownSlug      = "unknown"

	runIDPattern     = `/actions/runs/([0-9]+)`
	slugifyPattern   = `[^a-z0-9]+`
	runLinkLabel     = "run"
	runLinkFmt       = "run#%d"
	jobLinkLabel     = "job"
	markdownLinkFmt  = "[%s](%s)"
	linkPartsSep     = " / "
	linkEntriesSep   = ", "
	lineDateLabelFmt = "Jan-02"

	graphTopSeriesLimit                 = 5
	chartTitleTotalFailures             = "Total failures vs runs"
	chartTitleWorkflowFailures          = "Failures per workflow"
	chartTitleBranchWorkflowFails       = "Failures per branch and workflow"
	chartTitleWorkflowRunFailures       = "Workflow runs vs failures"
	chartSeriesNameFailures             = "Failures"
	chartSeriesNameSuccessfulRuns       = "Successful runs"
	chartSeriesNameRuns                 = "Runs"
	chartLineAxisLabel                  = "Failures"
	chartLineAxisLabelRuns              = "Runs"
	errorChartWidth                     = 800
	errorChartHeight                    = 80
	graphColorBackground                = "white"
	graphColorAxis                      = "#1f2937"
	graphColorTick                      = "#9ca3af"
	graphColorGrid                      = "#e5e7eb"
	graphColorRuns                      = "#2563eb"
	graphColorFailures                  = "#ef4444"
	graphColorSuccessfulRuns            = "#16a34a"
	graphColorSuccessfulRunsAreaOpacity = 0.2
	graphColorRunsTotal                 = "#111827"
	graphColorFailureGap                = "#ef4444"
	graphColorFailureGapOpacity         = 0.18
	graphColorRunsOpacity               = 0.35
	graphColorFailuresOpacity           = 0.8
)

var (
	defaultRepos      = []string{repoCilium, repoTetragon}
	defaultEvents     = []string{"schedule", "push", "workflow_dispatch"}
	defaultDays       = []int{7, 14, 30, 60, 90}
	defaultFailStatus = []string{"failure"}
	defaultTestStatus = []string{"failed", "error"}

	defaultReportSpecs = []reportSpec{
		{
			Title:      reportTitleCilium,
			Slug:       reportSlugCilium,
			Repository: repoCilium,
			Component:  compCilium,
		},
		{
			Title:      reportTitleTetragon,
			Slug:       reportSlugTetragon,
			Repository: repoTetragon,
			Component:  compTetragon,
		},
	}

	lineSeriesColors = []string{
		graphColorFailures,
		graphColorRuns,
		"#16a34a",
		"#f59e0b",
		"#7c3aed",
	}

	slugifyRegex = regexp.MustCompile(slugifyPattern)
	runIDRegex   = regexp.MustCompile(runIDPattern)
)
