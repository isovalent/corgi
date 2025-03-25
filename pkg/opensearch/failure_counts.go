package opensearch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"text/template"
	"time"

	"github.com/isovalent/corgi/pkg/types"
	"github.com/isovalent/corgi/pkg/util"
	"github.com/opensearch-project/opensearch-go"
	"github.com/opensearch-project/opensearch-go/opensearchapi"
)

type FailureCountResult struct {
	DocumentIdentifier string
	Total              int
	TotalFailures      int
	Rate               float64
}

// DocumentCountQueryTemplateParams is the parameters that need to be passed
// to the DocumentCountQueryTemplateText template.
type DocumentCountQueryTemplateParams struct {
	// Since is a cut-off time for when a document is pulled.
	// Only documents which are part of a workflow that started after this
	// time are pulled.
	Since string
	// Since is a cut-off time for when a document is pulled.
	// Only documents which are part of a workflow that started before this
	// time are pulled.
	Until string
	// LocalUTCOffset represents the time zone of the client making the
	LocalUTCOffset string
	// Type is the document type to pull, for example "workflow_run" or "job_run".
	// This is checked against each document's "type" field.
	Type string
	// Branch is the source git branch of the document, for example "main". This
	// is checked against each document's "head_branch" field.
	Branch string
	// Repository is the source git repository of the document, for example "cilium/cilium".
	// This is checked against each document's "repository.full_name" field.
	Repository string
	// Event is the type of event that triggered a workflow run for a document.
	// This is checked against each document's "event" field.
	Event string
	// GroupByField determines the field in which document counts are aggregated on,
	// for example "workflow_name.keyword".
	GroupByField string
	// ConclusionField determines the field which holds the document's conclusion, for
	// example "workflow_conclusion.keyword".
	ConclusionField string
	// ConclusionFailure determines the name of a failed conclusion in the document, for
	// example "failure".
	ConclusionFailure string
}

func NewDocumentCountQueryTemplateParams(
	since time.Time,
	until time.Time,
	typ types.TypeName,
	branch,
	repoOwner,
	repoName,
	event string,
) (*DocumentCountQueryTemplateParams, error) {
	var groupByField string
	var conclusionField string

	switch typ {
	case types.TypeNameWorkflowRun:
		groupByField = "workflow_name.keyword"
		conclusionField = "workflow_conclusion"
	case types.TypeNameJobRun:
		groupByField = "job_name.keyword"
		conclusionField = "job_conclusion"
	case types.TypeNameStepRun:
		groupByField = "step_name.keyword"
		conclusionField = "step_conclusion"
	default:
		return nil, fmt.Errorf("unknown document type: %s", typ)
	}

	return &DocumentCountQueryTemplateParams{
		Since:             since.Format("2006-01-02"),
		Until:             until.Format("2006-01-02"),
		LocalUTCOffset:    since.Format("-0700"),
		Type:              string(typ),
		Branch:            branch,
		Repository:        fmt.Sprintf("%s/%s", repoOwner, repoName),
		Event:             event,
		ConclusionFailure: "failure",
		GroupByField:      groupByField,
		ConclusionField:   conclusionField,
	}, nil
}

const (
	// documentCountQueryTemplateText creates an OpenSearch query which returns two
	// counts for a set of documents: the total number of documents in the set and
	// the total number of documents in the set that are representative of a failure.
	documentCountQueryTemplateText = `
	{
		"size": 0,
		"aggs": {
			"counts": {
				"filter": { "bool": { "must": [
					{ "range": {
						"workflow_run_started_at": {
							"lte": "{{ .Until }}",
							"gte": "{{ .Since }}",
							"format": "yyyy-MM-dd",
							"time_zone": "{{ .LocalUTCOffset }}"
						}
					} },
					{ "term": { "type.keyword": "{{ .Type }}" } },
					{ "term": { "head_branch.keyword": "{{ .Branch }}" } },
					{ "term": { "repository.full_name.keyword": "{{ .Repository }}" } },
					{ "term": { "event.keyword": "{{ .Event }}" } }
				] } },
				"aggs": {
					"total": { "terms": {
						"field": "{{ .GroupByField }}",
						"size": 9999
					} },
					"failure": {
						"filter": { "bool": { "must": [
							{ "term": { "{{ .ConclusionField }}": "{{ .ConclusionFailure }}" } }
						] } },
						"aggs": { "count": { "terms": {
							"field": "{{ .GroupByField }}",
							"size": 9999
						} } }
					}
				}
			}
		}
	}`
)

var (
	documentCountQueryTemplate = template.Must(
		template.New("documentCountQuery").Parse(
			strings.ReplaceAll(
				strings.ReplaceAll(
					strings.ReplaceAll(
						documentCountQueryTemplateText,
						" ", ""),
					"\t", ""),
				"\n", ""),
		),
	)
)

func DoFailureCountRequest(
	ctx context.Context,
	logger *slog.Logger,
	client *opensearch.Client,
	index string,
	templateParams *DocumentCountQueryTemplateParams,
) ([]FailureCountResult, error) {
	queryBytes := &bytes.Buffer{}
	if err := documentCountQueryTemplate.Execute(queryBytes, templateParams); err != nil {
		return nil, fmt.Errorf("unable to fill failure rate document count query template: %w", err)
	}

	queryStr := queryBytes.String()
	countReq := &opensearchapi.SearchRequest{
		Index: []string{index},
		Body:  strings.NewReader(queryStr),
	}

	logger.Debug("Issuing document count request", "requestBody", queryStr)

	counts, err := doGenericRequest(ctx, logger, client, countReq)
	if err != nil {
		return nil, fmt.Errorf("unable to get failure counts from OpenSearch: %w", err)
	}

	logger.Debug("Got response", "resp", counts)

	return parseFailureCountRequestResponse(counts)
}

func parseAggBuckets(bucketsArray any) (map[string]int, error) {
	result := map[string]int{}

	buckets, ok := bucketsArray.([]any)
	if !ok {
		return nil, errors.New("buckets array is not of type []map[string]any")
	}

	for _, _bucket := range buckets {
		bucket, ok := _bucket.(map[string]any)
		if !ok {
			return result, fmt.Errorf("bucket is not of type map[string]any: %s", _bucket)
		}

		_key, ok := bucket["key"]
		if !ok {
			return nil, fmt.Errorf("bucket is missing key 'key': %s", bucket)
		}

		key, ok := _key.(string)
		if !ok {
			return nil, fmt.Errorf("value for key with name 'key' in bucket is not string: %s", _key)
		}

		_count, ok := bucket["doc_count"]
		if !ok {
			return nil, fmt.Errorf("bucket is missing key 'doc_count': %s", bucket)
		}

		// These counts should always be ints, but for some reason they are
		// typed as floats.
		count, ok := _count.(float64)
		if !ok {
			return nil, fmt.Errorf("value for key with name 'doc_count' in bucket is not int: %s", _count)
		}

		result[key] = int(count)
	}

	return result, nil
}

func parseFailureCountRequestResponse(resp map[string]any) ([]FailureCountResult, error) {
	results := []FailureCountResult{}

	_aggs, ok := resp["aggregations"]
	if !ok {
		return nil, errors.New("key 'aggregations' missing in doc count response")
	}

	aggs, ok := _aggs.(map[string]any)
	if !ok {
		return nil, errors.New("aggregation is not of type map[string]any")
	}

	_aggResult, ok := aggs["counts"]
	if !ok {
		return nil, errors.New("key 'counts' missing in doc count response")
	}

	aggResult, ok := _aggResult.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("aggregation result is not of type map[string]any")
	}

	totalBucketsRaw, err := util.TraverseUnstructured("total.buckets", aggResult)
	if err != nil {
		return nil, fmt.Errorf("cannot find total counts in aggregation result: %w", err)
	}

	totals, err := parseAggBuckets(totalBucketsRaw)
	if err != nil {
		return nil, fmt.Errorf("unable to parse buckets in 'total' agg for aggregation result: %w", err)
	}

	failureBucketsRaw, err := util.TraverseUnstructured("failure.count.buckets", aggResult)
	if err != nil {
		return nil, fmt.Errorf("cannot find failure counts in aggregation result: %w", err)
	}

	failures, err := parseAggBuckets(failureBucketsRaw)
	if err != nil {
		return nil, fmt.Errorf("unable to parse buckets in 'failure' agg for aggregation result: %w", err)
	}

	for id, totalCount := range totals {
		// If the failure count cannot be found in the aggregation result,
		// then the number of failures is zero and OpenSearch omitted the result.
		failureCount, ok := failures[id]
		if !ok {
			failureCount = 0
		}

		results = append(
			results,
			FailureCountResult{
				DocumentIdentifier: id,
				Total:              totalCount,
				TotalFailures:      failureCount,
				Rate:               float64(failureCount) / float64(totalCount),
			},
		)
	}

	return results, nil
}
