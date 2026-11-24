package opensearch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/isovalent/corgi/pkg/types"
)

// maxIDBytes is the longest _id OpenSearch accepts.
const maxIDBytes = 512

type BulkEntry struct {
	Index string
	ID    string
	Verb  string
	Data  []byte
}

func (b *BulkEntry) Write(target io.Writer) (int, error) {
	if b == nil {
		return 0, nil
	}

	action, err := json.Marshal(map[string]map[string]string{
		b.Verb: {"_index": b.Index, "_id": b.ID},
	})
	if err != nil {
		return 0, fmt.Errorf("unable to marshal bulk action for '%s': %v", b.ID, err)
	}
	total, err := target.Write(append(action, '\n'))
	if err != nil {
		return total, err
	}
	n, err := target.Write(b.Data)
	total = total + n
	if err != nil {
		return total, err
	}
	n, err = target.Write([]byte("\n"))
	total = total + n
	return total, err
}

// shortenID keeps an ID under maxIDBytes by replacing its tail with a hash of the whole ID.
func shortenID(id string) string {
	if len(id) <= maxIDBytes {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	suffix := "-" + hex.EncodeToString(sum[:])
	prefix := id[:maxIDBytes-len(suffix)]
	for !utf8.ValidString(prefix) {
		prefix = prefix[:len(prefix)-1]
	}
	return prefix + suffix
}

// GetDocumentID returns a unique document ID for the given object.
// Equal objects have the same ID.
func GetDocumentID(obj any) (string, error) {
	id, err := documentID(obj)
	if err != nil {
		return "", err
	}
	return shortenID(id), nil
}

func documentID(obj any) (string, error) {
	switch o := obj.(type) {
	case *types.WorkflowRun:
		return fmt.Sprintf("%d-%d", o.ID, o.RunAttempt), nil
	case types.JobRun:
		return fmt.Sprintf("%d-%d-%d", o.WorkflowRun.ID, o.RunAttempt, o.ID), nil
	case types.StepRun:
		return fmt.Sprintf("%d-%d-%d-%d", o.WorkflowRun.ID, o.RunAttempt, o.ID, o.Number), nil
	case types.Testsuite:
		return fmt.Sprintf("%d-%d-%s", o.ID, o.RunAttempt, o.JUnitFilename), nil
	case types.Testcase:
		return fmt.Sprintf(
			"%d-%d-%s-%s",
			o.ID, o.RunAttempt, o.JUnitFilename, o.Name,
		), nil
	case types.FailureRate:
		return fmt.Sprintf(
			"%d-%s-%s-%s-%s-%s",
			o.Repository.ID, o.Event, o.HeadBranch,
			o.Since.Format("2006-01-02"), o.Until.Format("2006-01-02"),
			o.DocumentIdentifier,
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

		_, err = (&BulkEntry{
			Index: index,
			ID:    id,
			Verb:  "index",
			Data:  d,
		}).Write(target)
		if err != nil {
			return err
		}
	}

	return nil
}
