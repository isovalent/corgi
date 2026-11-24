package opensearch

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/isovalent/corgi/pkg/types"
)

func testcase(file, name string) types.Testcase {
	return types.Testcase{
		Testsuite: &types.Testsuite{
			WorkflowRun:   &types.WorkflowRun{ID: 43787053987, RunAttempt: 1},
			JUnitFilename: file,
		},
		Name: name,
	}
}

// bulkIDs returns the _id of each action line that BulkWriteObjects writes, as OpenSearch decodes it.
func bulkIDs(t *testing.T, objs []types.Testcase) []string {
	t.Helper()
	var buf bytes.Buffer
	if err := BulkWriteObjects(objs, "runs-oss", &buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2*len(objs) {
		t.Fatalf("got %d lines for %d objects", len(lines), len(objs))
	}
	var ids []string
	for i := 0; i < len(lines); i += 2 {
		var action map[string]struct {
			Index string `json:"_index"`
			ID    string `json:"_id"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &action); err != nil {
			t.Fatalf("action line %q is not valid JSON: %v", lines[i], err)
		}
		if action["index"].Index != "runs-oss" {
			t.Fatalf("action line %q has no index action for runs-oss", lines[i])
		}
		ids = append(ids, action["index"].ID)
	}
	return ids
}

func TestBulkWriteObjectsEscapesIDs(t *testing.T) {
	cases := []struct{ file, name, want string }{
		{
			"conn-disrupt-test-Setup & Test-ipsec.xml", "client-egress",
			"43787053987-1-conn-disrupt-test-Setup & Test-ipsec.xml-client-egress",
		},
		{
			"unit.xml", `always_=>_[\x1b[31m_\x1b[32m_`,
			`43787053987-1-unit.xml-always_=>_[\x1b[31m_\x1b[32m_`,
		},
		{
			"unit.xml", `parse_0,_-,_""`,
			`43787053987-1-unit.xml-parse_0,_-,_""`,
		},
	}
	var objs []types.Testcase
	for _, c := range cases {
		objs = append(objs, testcase(c.file, c.name))
	}
	for i, id := range bulkIDs(t, objs) {
		if id != cases[i].want {
			t.Errorf("got _id %q, want %q", id, cases[i].want)
		}
	}
}

func TestGetDocumentIDLimitsLength(t *testing.T) {
	long := strings.Repeat("é", 300)
	ids := bulkIDs(t, []types.Testcase{
		testcase("unit.xml", long+"a"),
		testcase("unit.xml", long+"b"),
		testcase("unit.xml", long+"a"),
	})
	for _, id := range ids {
		if len(id) > maxIDBytes || !utf8.ValidString(id) {
			t.Fatalf("_id of %d bytes (valid UTF-8: %v) exceeds the %d-byte limit or is invalid",
				len(id), utf8.ValidString(id), maxIDBytes)
		}
	}
	if ids[0] == ids[1] {
		t.Errorf("distinct test cases share _id %q", ids[0])
	}
	if ids[0] != ids[2] {
		t.Errorf("equal test cases got different IDs %q and %q", ids[0], ids[2])
	}
	if !strings.HasPrefix(ids[0], "43787053987-1-unit.xml-é") {
		t.Errorf("shortened _id %q lost its prefix", ids[0])
	}
}
