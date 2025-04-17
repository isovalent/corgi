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

func TestParseFile(t *testing.T) {
	tests := []struct {
		path          string
		tests         int
		failures      int
		expectedError error
	}{
		{
			"testdata/ci-eks-passed.xml",
			114,
			0,
			nil,
		},
		{
			"testdata/ci-eks-failed.xml",
			114,
			1,
			nil,
		},
		{
			"testdata/ci-eks-failed-no-owners.xml",
			114,
			1,
			nil,
		},
		{
			"testdata/ci-eks-failed-invalid.xml",
			114,
			1,
			nil,
		},
		{
			"testdata/ci-privileged.xml",
			7220,
			0,
			nil,
		},
		{
			"testdata/unit-test.xml",
			44,
			1,
			nil,
		},
	}
	for _, tt := range tests {
		t.Log("Path: " + tt.path)
		f, err := NewTestFile(tt.path)
		assert.NoError(t, err)
		suites, cases, err := parseFile(f, dummyWorkflowRun, dummyConclusions, logger)
		assert.ErrorIs(t, err, tt.expectedError)

		assert.Equal(t, tt.tests, len(cases))
		assert.Equal(t, tt.failures, suites[0].TotalFailures)
	}
}

func TestParseFailureData(t *testing.T) {
	input := "check-log-errors/no-errors-in-logs/kind-kind/kube-system/cilium-xxxxx (cilium-agent);metadata;Owners: @ci/owner1 (no-errors-in-logs), @ci/owner2 (no-errors-in-logs)"

	owners, tests, err := parseFailureData("check-log-errors", input)
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

func TestParseProperties(t *testing.T) {
	path := "testdata/all-owners.xml"

	f, err := NewTestFile(path)
	assert.NoError(t, err)
	_, cases, err := parseFile(f, dummyWorkflowRun, dummyConclusions, logger)
	assert.NoError(t, err)

	// Example has no workflow owners
	//assert.NotEmpty(t, suites[0].Owners)

	for _, tt := range cases {
		assert.NotEmpty(t, tt.Owners)
	}
}

func TestFilterOwners(t *testing.T) {
	input := "check-log-errors/no-errors-in-logs/kind-kind/kube-system/cilium-xxxxx (cilium-agent);metadata;Owners: @ci/owner1 (no-errors-in-logs), @ci/owner2 (.github/foo)"

	owners, tests, err := parseFailureData("check-log-errors", input)
	assert.NoError(t, err)

	testOwners := filterTestOwners(owners, tests)
	assert.Contains(t, testOwners, "@ci/owner1")
	assert.Len(t, testOwners, 1)

	wfOwners := filterWorkflowOwners(owners, tests)
	assert.Contains(t, wfOwners, "@ci/owner2")
	assert.Len(t, wfOwners, 1)
}
