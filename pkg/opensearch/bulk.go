package opensearch

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/isovalent/oss-ci-opensearch/pkg/types"
)

type BulkEntry struct {
	Index string
	ID    string
	Verb  string
	Data  []byte
}

func (b *BulkEntry) Write(target io.Writer) {
	if b == nil {
		return
	}

	builder := strings.Builder{}
	builder.WriteString("{ \"")
	builder.WriteString(b.Verb)
	builder.WriteString("\" : { \"_index\": \"")
	builder.WriteString(b.Index)
	builder.WriteString("\", \"_id\": \"")
	builder.WriteString(b.ID)
	builder.WriteString("\" } }\n")

	target.Write([]byte(builder.String()))
	target.Write(b.Data)
	target.Write([]byte("\n"))
}

func jsonEscapeString(i string) (string, error) {
	if len(i) == 0 {
		return "", nil
	}

	b, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("unable to escape string '%s': %v", i, err)
	}
	// Trim the beginning and trailing " character
	return string(b[1 : len(b)-1]), nil
}

// GetDocumentID returns a unique document ID for the given object.
// Equal objects have the same ID.
func GetDocumentID(obj any) (string, error) {
	switch o := obj.(type) {
	case *types.WorkflowRun:
		return fmt.Sprintf("%d-%d", o.ID, o.RunAttempt), nil
	case types.JobRun:
		return fmt.Sprintf("%d-%d-%d", o.WorkflowRun.ID, o.WorkflowRun.RunAttempt, o.ID), nil
	case types.StepRun:
		return fmt.Sprintf("%d-%d-%d-%d", o.WorkflowRun.ID, o.WorkflowRun.RunAttempt, o.ID, o.Number), nil
	case types.Testsuite:
		junitFilename, err := jsonEscapeString(o.JUnitFilename)
		if err != nil {
			return "", fmt.Errorf("unable to get document id for Testsuite: %v", err)
		}
		return fmt.Sprintf("%d-%d-%s", o.WorkflowRun.ID, o.WorkflowRun.RunAttempt, junitFilename), nil
	case types.Testcase:
		junitFilename, err := jsonEscapeString(o.Testsuite.JUnitFilename)
		if err != nil {
			return "", fmt.Errorf("unable to get document id for Testsuite in Testcase: %v", err)
		}
		return fmt.Sprintf(
			"%d-%d-%s-%s",
			o.WorkflowRun.ID, o.WorkflowRun.RunAttempt, junitFilename, o.Name,
		), nil
	case types.FailureRate:
		docIdentifier, err := jsonEscapeString(o.DocumentIdentifier)
		if err != nil {
			return "", fmt.Errorf("unable to get document id for failure rate: %v", err)
		}
		return fmt.Sprintf(
			"%d-%s-%s-%s-%s-%s",
			o.Repository.ID, o.Event, o.HeadBranch,
			o.Since.Format("2006-01-02"), o.Until.Format("2006-01-02"),
			docIdentifier,
		), nil
	}

	return "", fmt.Errorf("unable to determine document ID for object '%v'", obj)
}

func BulkWriteObjects[T any](objs []T, index string, target io.Writer) error {
	for _, obj := range objs {
		d, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("unable to marshal obj '%v': %v", obj, err)
		}

		id, err := GetDocumentID(obj)
		if err != nil {
			return err
		}

		(&BulkEntry{
			Index: index,
			ID:    id,
			Verb:  "index",
			Data:  d,
		}).Write(target)
	}

	return nil
}
