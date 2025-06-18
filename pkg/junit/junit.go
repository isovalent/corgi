package junit

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/isovalent/corgi/pkg/types"
	"github.com/isovalent/corgi/pkg/util"
)

var (
	ErrInvalidFailureData = errors.New("unsupported format for testcase.failure.data")
	ErrUnbalancedOwners   = errors.New("expected list of '@<owner> (<test>)'")

	metadataDelimiter   = ";metadata;"
	reFailureDataOwners = regexp.MustCompile(`@[-a-zA-Z\/0-9]*`)
	reFailureDataTests  = regexp.MustCompile(`\(([-a-zA-Z\/0-9.]*)\)`)
)

func parseOwners(data string) []string {
	return reFailureDataOwners.FindAllString(data, -1)
}

func parseTestNames(data string) []string {
	match := reFailureDataTests.FindAllStringSubmatch(data, -1)
	result := make([]string, 0, len(match))
	for _, m := range match {
		result = append(result, m[1])
	}
	return result
}

func parseOwnerProperties(testname, data string) (owners, testNames []string, err error) {
	// Expected input:
	// @cilium/sig-agent (host-to-pod)
	owners = parseOwners(data)
	testNames = parseTestNames(data)

	if len(owners) == 0 {
		return nil, nil, fmt.Errorf("%w: found %v/%v", ErrUnbalancedOwners, owners, testNames)
	}

	if len(owners) != len(testNames) {
		// Input was missing test name; came in this form:
		// @cilium/agent
		testNames = make([]string, 0, len(owners))
		for range len(owners) {
			testNames = append(testNames, testname)
		}
	}

	return owners, testNames, nil
}

func parseFailureData(testname, data string) (owners, testNames []string, err error) {
	// Expected input:
	// check-log-errors/no-errors-in-logs/kind-kind/kube-system/cilium-xxxxx (cilium-agent);metadata;Owners: @ci/owner1 (no-errors-in-logs), @ci/owner2 (no-errors-in-logs)
	parsed := strings.Split(data, metadataDelimiter)
	if len(parsed) <= 1 {
		return nil, nil, ErrInvalidFailureData
	}

	return parseOwnerProperties(testname, parsed[1])
}

func filterOwners(prefix string, owners, tests []string, match bool) []string {
	result := make([]string, 0, len(owners))
	for i, o := range owners {
		has := strings.HasPrefix(tests[i], prefix)
		if has == match {
			result = append(result, o)
		}
	}
	return result
}

func filterWorkflowOwners(owners, tests []string) []string {
	return filterOwners(".github", owners, tests, true)
}

func filterTestOwners(owners, tests []string) []string {
	return filterOwners(".github", owners, tests, false)
}

func parseTime(timestamp string) (result time.Time, err error) {
	// Expected:
	// "2006-01-02T15:04:05"
	// "2006-01-02T15:04:05Z"
	// "2006-01-02T15:04:0507:00"
	for _, fmt := range []string{
		"2006-01-02T15:04:05",
		time.RFC3339,
	} {
		result, err = time.Parse(fmt, timestamp)
		if err == nil {
			return result, nil
		}
	}
	return result, err
}

func parseTestsuite(
	suite *Testsuite,
	run *types.WorkflowRun,
	allowedTestConclusions []string,
	l *slog.Logger,
) (*types.Testsuite, []types.Testcase, error) {
	s := &types.Testsuite{
		WorkflowRun:   run,
		Type:          types.TypeNameTestsuite,
		Name:          suite.Name,
		TotalTests:    suite.Tests,
		TotalFailures: suite.Failures,
		TotalErrors:   suite.Errors,
		TotalSkipped:  suite.Skipped,
	}

	if suite.Time != "" {
		duration, err := time.ParseDuration(fmt.Sprintf("%ss", suite.Time))
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse duration '%ss': %w", suite.Time, err)
		}
		s.Duration = duration
	}

	if suite.Timestamp != "" {
		endTime, err := parseTime(suite.Timestamp)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse timestamp '%s': %w", suite.Timestamp, err)
		}
		s.EndTime = endTime
	}

	cases := []types.Testcase{}
	allOwners := make(map[string]struct{})

	if suite.Properties != nil {
		for _, p := range *suite.Properties {
			if p.Name == "owner" {
				owners, _, err := parseOwnerProperties(suite.Name, p.Value)
				if err != nil {
					l.Warn("Could not parse owners from testsuite properties", "data", p.Value, "error", err)
				}
				for _, o := range owners {
					allOwners[o] = struct{}{}
				}
			}
		}
	}

	for _, testcase := range suite.Testcases {
		tc := types.Testcase{
			Testsuite: s,
			Type:      types.TypeNameTestcase,
			Name:      testcase.Name,
		}

		// There are a couple of formats for the cilium-junits. Sometimes
		// the Status property is set, and other times it isn't. It if isn't set,
		// the status will be exposed through the different
		// result fields of the junit.Testcase.

		if testcase.Status != "" {
			tc.Status = testcase.Status
		} else {
			if testcase.Error != nil {
				tc.Status = "error"
			} else if testcase.Failure != nil {
				tc.Status = "failure"
			} else if testcase.Skipped != nil {
				tc.Status = "skipped"
			} else {
				tc.Status = "passed"
			}
		}

		if testcase.Failure != nil {
			tc.FailureMessages = testcase.Failure.FailureMessages
		}

		if !util.Contains(allowedTestConclusions, tc.Status) {
			l.Debug(
				"Skipping test case for workflow, does not meet status criteria",
				"testcase-name", testcase.Name, "testcase-status", testcase.Status,
			)

			continue
		}

		if testcase.Time != "" {
			duration, err := time.ParseDuration(fmt.Sprintf("%ss", testcase.Time))
			if err != nil {
				return nil, nil, fmt.Errorf("unable to parse duration '%ss': %w", testcase.Time, err)
			}
			tc.Duration = duration
		}

		if testcase.Failure != nil {
			// Parse owners
			owners, testNames, err := parseFailureData(testcase.Name, testcase.Failure.Data)
			if err == nil {
				tc.Owners = filterTestOwners(owners, testNames)
				for _, o := range filterWorkflowOwners(owners, testNames) {
					allOwners[o] = struct{}{}
				}
			} else {
				l.Warn("Could not parse owners from testcase failure data", "data", testcase.Failure.Data, "error", err)
			}
		}

		if testcase.Properties != nil {
			for _, p := range testcase.Properties.Properties {
				if p.Name == "owner" {
					owners, testNames, err := parseOwnerProperties(testcase.Name, p.Value)
					if err == nil {
						tc.Owners = filterTestOwners(owners, testNames)
						for _, o := range filterWorkflowOwners(owners, testNames) {
							allOwners[o] = struct{}{}
						}
					} else {
						l.Warn("Could not parse owners from testcase properties", "data", p.Value, "error", err)
					}
				}
			}
		}

		cases = append(cases, tc)
	}

	s.Owners = slices.Sorted(maps.Keys(allOwners))

	return s, cases, nil
}

type file interface {
	Open() (io.ReadCloser, error)
	FileInfo() fs.FileInfo
}

func parseFile(
	fil file,
	run *types.WorkflowRun,
	allowedTestConclusions []string,
	l *slog.Logger,
) ([]types.Testsuite, []types.Testcase, error) {
	suites := []types.Testsuite{}
	cases := []types.Testcase{}

	if !strings.HasSuffix(fil.FileInfo().Name(), ".xml") || fil.FileInfo().IsDir() {
		l.Debug("ignoring non-xml file in cilium-junits archive", "file", fil.FileInfo().Name())
		return nil, nil, nil
	}

	l.Info("Parsing JUnit file", "name", fil.FileInfo().Name())

	fileReader, err := fil.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open file %q: %w", fil.FileInfo().Name(), err)
	}
	defer func() {
		if err2 := fileReader.Close(); err2 != nil {
			l.Debug("Failed to close junit file", "path", fil.FileInfo().Name(), "error", err2)
		}
	}()

	buf := &bytes.Buffer{}

	_, err = io.Copy(buf, fileReader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read junit file %q: %w", fil.FileInfo().Name(), err)
	}

	// Sometimes a JUnit file can be empty, so we need to rule out empty files.
	if buf.Len() == 0 {
		l.Debug("ignoring empty xml file", "file", fil.FileInfo().Name())
		return nil, nil, nil
	}

	// A JUnit file may either be:
	// 1. A junit.Testsuites object with multiple junit.Testsuite objects.
	// 2. A junit.Testsuites object with a single junit.Testsuite object.
	// 3. A single junit.Testsuite.
	// Try all options when unmarshalling.
	// Note that the XML parser thinks the Testsuites object is a valid Testsuite object, so
	// we have to try parsing into a Testsuites first.
	toParse := []Testsuite{}
	s := Testsuites{}
	if err := xml.Unmarshal(buf.Bytes(), &s); err != nil {
		s := Testsuite{}
		if err2 := xml.Unmarshal(buf.Bytes(), &s); err2 != nil {
			e := errors.Join(err, err2)
			return nil, nil, fmt.Errorf("unable to unmarshal junit file '%s' in artifact to Testsuite or Testsuites object: %w", fil.FileInfo().Name(), e)
		}
		toParse = append(toParse, s)
	} else {
		toParse = s.Suites
	}

	for _, s := range toParse {
		parsedSuite, parsedCases, err := parseTestsuite(&s, run, allowedTestConclusions, l)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse test suite in junit file '%s': %w", fil.FileInfo().Name(), err)
		}

		parsedSuite.JUnitFilename = fil.FileInfo().Name()
		suites = append(suites, *parsedSuite)
		cases = append(cases, parsedCases...)
	}

	return suites, cases, nil
}

func ParseFiles[F file](
	files []F,
	run *types.WorkflowRun,
	allowedTestConclusions []string,
	l *slog.Logger,
) ([]types.Testsuite, []types.Testcase, error) {
	suites := []types.Testsuite{}
	cases := []types.Testcase{}

	for _, f := range files {
		s, c, err := parseFile(f, run, allowedTestConclusions, l)
		if err != nil {
			return nil, nil, err
		}
		suites = append(suites, s...)
		cases = append(cases, c...)
	}

	return suites, cases, nil
}
