package junit

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/corgi/pkg/types"
)

var (
	dummyWorkflowRun = &types.WorkflowRun{
		Name: "test-workflow",
	}
	dummyConclusions = []string{"passed", "failed", "skipped"}

	logger = slog.New(slog.NewTextHandler(
		os.Stderr, &slog.HandlerOptions{},
	))
)

type testFile struct {
	*os.File
	info os.FileInfo
}

func NewTestFile(path string) (testFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return testFile{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return testFile{}, err
	}

	return testFile{
		File: f,
		info: info,
	}, nil
}

func (t testFile) FileInfo() os.FileInfo {
	return t.info
}

func (t testFile) Open() (io.ReadCloser, error) {
	return t.File, nil
}

func TestParseFileSuccess(t *testing.T) {
	path := "testdata/ci-eks-passed.xml"

	f, err := NewTestFile(path)
	assert.NoError(t, err)
	suites, cases, err := parseFile(f, dummyWorkflowRun, dummyConclusions, logger)
	assert.NoError(t, err)

	assert.Greater(t, suites[0].TotalTests, 0)
	assert.Equal(t, suites[0].TotalFailures, 0)
	assert.Greater(t, len(cases), 0)
}

func TestParseFileFailure(t *testing.T) {
	path := "testdata/ci-eks-failed.xml"

	f, err := NewTestFile(path)
	assert.NoError(t, err)
	suites, cases, err := parseFile(f, dummyWorkflowRun, dummyConclusions, logger)
	assert.NoError(t, err)

	assert.Greater(t, suites[0].TotalTests, 0)
	assert.Greater(t, suites[0].TotalFailures, 0)
	assert.Greater(t, len(cases), 0)
}

func TestParseFailureData(t *testing.T) {
	input := "check-log-errors/no-errors-in-logs/kind-kind/kube-system/cilium-xxxxx (cilium-agent);metadata;Owners: @ci/owner1 (no-errors-in-logs), @ci/owner2 (no-errors-in-logs)"

	owners, tests, err := parseFailureData(input)
	assert.NoError(t, err)
	assert.Contains(t, owners, "@ci/owner1")
	assert.Contains(t, owners, "@ci/owner2")
	assert.Contains(t, tests, "no-errors-in-logs")
}

func TestParseTestSuiteCodeOwners(t *testing.T) {
	path := "testdata/ci-eks-failed.xml"

	f, err := NewTestFile(path)
	assert.NoError(t, err)
	suites, cases, err := parseFile(f, dummyWorkflowRun, dummyConclusions, logger)
	assert.NoError(t, err)

	assert.NotEmpty(t, suites[0].Owners)

	var failed types.Testcase
	for _, tt := range cases {
		if tt.Status == "failed" {
			failed = tt
			break
		}
	}
	assert.NotEmpty(t, failed.Owners)
}

func TestFilterOwners(t *testing.T) {
	input := "check-log-errors/no-errors-in-logs/kind-kind/kube-system/cilium-xxxxx (cilium-agent);metadata;Owners: @ci/owner1 (no-errors-in-logs), @ci/owner2 (.github/foo)"

	owners, tests, err := parseFailureData(input)
	assert.NoError(t, err)

	testOwners := filterTestOwners(owners, tests)
	assert.Contains(t, testOwners, "@ci/owner1")
	assert.Len(t, testOwners, 1)

	wfOwners := filterWorkflowOwners(owners, tests)
	assert.Contains(t, wfOwners, "@ci/owner2")
	assert.Len(t, wfOwners, 1)
}
