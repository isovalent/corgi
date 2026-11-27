#!/usr/bin/env bash

set -euo pipefail

fail() {
  echo "$*" >&2
  exit 1
}

curl_opensearch() {
  curl --silent --show-error --fail-with-body \
    --user "$OPENSEARCH_USER:$OPENSEARCH_PASS" "$@"
}

count_query() {
  local index="$1"
  local query="$2"
  curl_opensearch \
    --header 'Content-Type: application/json' \
    --request POST \
    --data "$query" \
    "$OPENSEARCH_URL/$index/_count" | jq --exit-status -r '.count'
}

count_all() {
  curl_opensearch "$OPENSEARCH_URL/$1/_count" | jq --exit-status -r '.count'
}

count_type() {
  local query
  query=$(jq -cn --arg type "$2" '{query:{term:{"type.keyword":$type}}}')
  count_query "$1" "$query"
}

run_document_query() {
  local type="$1"
  shift
  local required_fields
  required_fields=$(printf '%s\n' "$@" | jq -R . | jq -s .)

  jq -cn \
    --arg type "$type" \
    --arg repository "$TARGET_REPOSITORY" \
    --arg branch "$TARGET_BRANCH" \
    --argjson fields "$required_fields" \
    '{query:{bool:{filter:([
      {term:{"type.keyword":$type}},
      {term:{"repository.full_name.keyword":$repository}},
      {term:{"head_branch.keyword":$branch}},
      {term:{"event.keyword":"push"}}
    ] + ($fields | map({exists:{field:.}})))}}}'
}

validate_run_document_type() {
  local type="$1"
  shift
  local total valid query
  total=$(count_type "$TARGET_RUNS_INDEX" "$type")
  query=$(run_document_query "$type" "$@")
  valid=$(count_query "$TARGET_RUNS_INDEX" "$query")

  printf 'Validated %s documents: %s/%s have expected source and required fields\n' \
    "$type" "$valid" "$total"
  [ "$total" -gt 0 ] || fail "No $type documents were indexed"
  [ "$valid" -eq "$total" ] ||
    fail "$valid of $total $type documents match the expected repository, branch, event, and fields"
  VALIDATED_RUN_DOCUMENTS=$((VALIDATED_RUN_DOCUMENTS + total))
}

build() {
  make --always-make GO_BUILD_FLAGS=-buildvcs=false build
}

scrape_runs() {
  ./corgi workflow runs \
    --repository "$TARGET_REPOSITORY" \
    --branch "$TARGET_BRANCH" \
    --since "$(date -u -d '4 hours ago' '+%Y-%m-%dT%H')" \
    --until "$(date -u '+%Y-%m-%dT%H')" \
    --events push \
    --run-statuses completed \
    --index "$TARGET_RUNS_INDEX" \
    --verbose > runs-results.json
  [ -s runs-results.json ] || fail "Corgi produced no workflow run documents"
}

validate_runs() {
  curl_opensearch --request POST "$OPENSEARCH_URL/$TARGET_RUNS_INDEX/_refresh" >/dev/null
  VALIDATED_RUN_DOCUMENTS=0
  validate_run_document_type workflow_run \
    workflow_id workflow_name workflow_status workflow_link workflow_run_started_at
  validate_run_document_type job_run \
    workflow_id job_id job_name job_status workflow_link
  validate_run_document_type step_run \
    workflow_id job_id job_name step_name step_number step_status
  validate_run_document_type test_suite \
    workflow_id test_suite_name test_suite_junit_filename workflow_link
  validate_run_document_type test_case \
    workflow_id test_suite_name test_suite_junit_filename test_case_name test_case_status workflow_link

  total=$(count_all "$TARGET_RUNS_INDEX")
  [ "$total" -eq "$VALIDATED_RUN_DOCUMENTS" ] ||
    fail "Runs index has $total documents, but only $VALIDATED_RUN_DOCUMENTS validated documents across the expected types"
  echo "Validated all $total documents in $TARGET_RUNS_INDEX"
}

failure_rates() {
  local until since days
  : > rates-results.json
  until=$(date -u '+%Y-%m-%d')
  for days in 1 3 7; do
    since=$(date -u -d "-$days days" '+%Y-%m-%d')
    ./corgi failure-rate \
      --repository "$TARGET_REPOSITORY" \
      --branch "$TARGET_BRANCH" \
      --until "$until" \
      --since "$since" \
      --events push \
      --runs-index "$TARGET_RUNS_INDEX" \
      --index "$TARGET_RATES_INDEX" \
      --types workflow_run,job_run,step_run \
      --verbose >> rates-results.json
  done
  [ -s rates-results.json ] || fail "Corgi produced no failure-rate documents"
}

failure_rate_query() {
  jq -cn \
    --arg test_type "$1" \
    --arg repository "$TARGET_REPOSITORY" \
    --arg branch "$TARGET_BRANCH" \
    --arg name_field "$2" \
    '{query:{bool:{filter:(
      [
        {term:{"type.keyword":"failure_rate"}},
        {term:{"test_type.keyword":$test_type}},
        {term:{"repository.full_name.keyword":$repository}},
        {term:{"head_branch.keyword":$branch}},
        {term:{"event.keyword":"push"}},
        {range:{"failure_rate":{gte:0,lte:1}}},
        {range:{"total_runs":{gte:1}}},
        {range:{"total_failures":{gte:0}}}
      ] + (["document_identifier","since","until","time_span_days","failure_rate","total_runs","total_failures",$name_field] | map({exists:{field:.}}))
    )}}}'
}

validate_failure_rate_type() {
  local test_type="$1"
  local name_field="$2"
  local query total_query total valid
  query=$(failure_rate_query "$test_type" "$name_field")
  total_query=$(jq -cn --arg test_type "$test_type" \
    '{query:{bool:{filter:[{term:{"type.keyword":"failure_rate"}},{term:{"test_type.keyword":$test_type}}]}}}')
  total=$(count_query "$TARGET_RATES_INDEX" "$total_query")
  valid=$(count_query "$TARGET_RATES_INDEX" "$query")
  printf 'Validated %s failure rates: %s/%s have valid fields and values\n' \
    "$test_type" "$valid" "$total"
  [ "$total" -gt 0 ] || fail "No failure-rate documents for $test_type were indexed"
  [ "$valid" -eq "$total" ] ||
    fail "$valid of $total $test_type failure-rate documents have valid values and required fields"
  VALIDATED_RATE_DOCUMENTS=$((VALIDATED_RATE_DOCUMENTS + total))
}

validate_rates() {
  curl_opensearch --request POST "$OPENSEARCH_URL/$TARGET_RATES_INDEX/_refresh" >/dev/null

  VALIDATED_RATE_DOCUMENTS=0
  validate_failure_rate_type workflow_run workflow_name
  validate_failure_rate_type job_run job_name
  validate_failure_rate_type step_run step_name

  local days count total
  for days in 1 3 7; do
    local span_query
    span_query=$(jq -cn --argjson days "$days" \
      '{query:{bool:{filter:[{term:{"type.keyword":"failure_rate"}},{term:{"time_span_days":$days}}]}}}')
    count=$(count_query "$TARGET_RATES_INDEX" "$span_query")
    [ "$count" -gt 0 ] || fail "No failure-rate documents for the ${days}-day window"
    echo "Found $count failure-rate documents for the ${days}-day window"
  done

  total=$(count_type "$TARGET_RATES_INDEX" failure_rate)
  [ "$total" -eq "$VALIDATED_RATE_DOCUMENTS" ] ||
    fail "Rates index has $total documents, but only $VALIDATED_RATE_DOCUMENTS validated documents"
  echo "Validated all $total documents in $TARGET_RATES_INDEX"
}

retention() {
  local fixture_query fixture_count
  fixture_query='{"query":{"term":{"integration_fixture":true}}}'
  fixture_count=$(count_query "$TARGET_RUNS_INDEX" "$fixture_query")
  if [ "$fixture_count" -gt 0 ]; then
    curl_opensearch --request DELETE \
      "$OPENSEARCH_URL/$TARGET_RUNS_INDEX/_doc/retention-fixture?refresh=wait_for" >/dev/null
  fi

  local before_total after_total before_workflows before_jobs before_steps before_suites before_cases
  before_total=$(count_all "$TARGET_RUNS_INDEX")
  before_workflows=$(count_type "$TARGET_RUNS_INDEX" workflow_run)
  before_jobs=$(count_type "$TARGET_RUNS_INDEX" job_run)
  before_steps=$(count_type "$TARGET_RUNS_INDEX" step_run)
  before_suites=$(count_type "$TARGET_RUNS_INDEX" test_suite)
  before_cases=$(count_type "$TARGET_RUNS_INDEX" test_case)

  local response
  response=$(curl_opensearch \
    --header 'Content-Type: application/json' \
    --request PUT \
    --data '{"workflow_run_started_at":"2000-01-01T00:00:00Z","integration_fixture":true}' \
    "$OPENSEARCH_URL/$TARGET_RUNS_INDEX/_doc/retention-fixture?refresh=wait_for")
  printf '%s' "$response" | jq --exit-status --arg id retention-fixture '._id == $id' >/dev/null ||
    fail "OpenSearch did not confirm the retention fixture was indexed"

  fixture_query='{"query":{"term":{"integration_fixture":true}}}'
  fixture_count=$(count_query "$TARGET_RUNS_INDEX" "$fixture_query")
  [ "$fixture_count" -eq 1 ] || fail "Expected one expired retention fixture, found $fixture_count"

  DRY_RUN=false ./.github/scripts/trim-runs-index.sh "$TARGET_RUNS_INDEX"
  curl_opensearch --request POST "$OPENSEARCH_URL/$TARGET_RUNS_INDEX/_refresh" >/dev/null

  fixture_count=$(count_query "$TARGET_RUNS_INDEX" "$fixture_query")
  [ "$fixture_count" -eq 0 ] || fail "Retention left the expired fixture indexed"
  after_total=$(count_all "$TARGET_RUNS_INDEX")
  [ "$after_total" -eq "$before_total" ] ||
    fail "Retention changed non-fixture document count from $before_total to $after_total"

  [ "$(count_type "$TARGET_RUNS_INDEX" workflow_run)" -eq "$before_workflows" ] || fail "Retention changed workflow-run records"
  [ "$(count_type "$TARGET_RUNS_INDEX" job_run)" -eq "$before_jobs" ] || fail "Retention changed job-run records"
  [ "$(count_type "$TARGET_RUNS_INDEX" step_run)" -eq "$before_steps" ] || fail "Retention changed step-run records"
  [ "$(count_type "$TARGET_RUNS_INDEX" test_suite)" -eq "$before_suites" ] || fail "Retention changed test-suite records"
  [ "$(count_type "$TARGET_RUNS_INDEX" test_case)" -eq "$before_cases" ] || fail "Retention changed test-case records"
  echo "Retention deleted the expired fixture and preserved all $before_total workflow and test documents"
}

case "${1:-}" in
  build) build ;;
  scrape-runs) scrape_runs ;;
  validate-runs) validate_runs ;;
  failure-rates) failure_rates ;;
  validate-rates) validate_rates ;;
  retention) retention ;;
  *) fail "usage: $0 {build|scrape-runs|validate-runs|failure-rates|validate-rates|retention}" ;;
esac
