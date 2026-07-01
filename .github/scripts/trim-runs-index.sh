#!/usr/bin/env bash
#
# Trims documents older than a retention window from the given OpenSearch runs
# indices and reclaims the freed disk space.
#
# Without retention these indices grow unbounded until the data node crosses its
# flood-stage disk watermark, at which point OpenSearch marks the index
# read-only and every bulk write from the scrape job fails. See
# .github/opensearch/README.md.
#
# Usage:
#   OPENSEARCH_URL=https://opensearch.example.com \
#   OPENSEARCH_USER=user OPENSEARCH_PASS=pass \
#   RETENTION_DAYS=190 [DRY_RUN=true] \
#     .github/scripts/trim-runs-index.sh runs-oss [more-indices...]
#
# DRY_RUN=true only counts the matching documents and deletes nothing, which is
# the safe way to try this out locally.

set -uo pipefail

: "${OPENSEARCH_URL:?OPENSEARCH_URL must be set}"
: "${OPENSEARCH_USER:?OPENSEARCH_USER must be set}"
: "${OPENSEARCH_PASS:?OPENSEARCH_PASS must be set}"
: "${RETENTION_DAYS:?RETENTION_DAYS must be set}"
DRY_RUN="${DRY_RUN:-false}"

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <index> [index...]" >&2
  exit 2
fi

if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]]; then
  echo "RETENTION_DAYS must be a positive integer, got '$RETENTION_DAYS'" >&2
  exit 2
fi

cutoff="now-${RETENTION_DAYS}d/d"

# Every document type corgi writes (WorkflowRun, JobRun, StepRun, Testsuite,
# Testcase) embeds the parent workflow run, so all of them carry
# workflow_run_started_at and this single query trims them together.
query='{"query":{"range":{"workflow_run_started_at":{"lt":"'"$cutoff"'"}}}}'

# curl wrapper. --fail-with-body makes curl exit non-zero on an HTTP error
# while still printing the response body, so failures are both detectable and
# debuggable. Credentials are passed via stdin-free env expansion rather than
# being echoed by set -x.
oscurl() {
  curl -sS --fail-with-body \
    -u "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
    -H "Content-Type: application/json" "$@"
}

# Trims a single index. Returns non-zero on failure so the caller can record it
# and still continue with the remaining indices.
trim_index() {
  local index="$1"

  echo "Index ${index} before trim:"
  oscurl "${OPENSEARCH_URL}/_cat/indices/${index}?v&h=index,docs.count,docs.deleted,store.size" || true

  # Capture curl and jq separately so a failed request is never mistaken for a
  # document count.
  local count_response match
  if ! count_response=$(oscurl -XGET "${OPENSEARCH_URL}/${index}/_count" -d "$query"); then
    echo "failed to count documents in ${index}: ${count_response}" >&2
    return 1
  fi
  if ! match=$(printf '%s' "$count_response" | jq -er '.count'); then
    echo "unexpected _count response for ${index}: ${count_response}" >&2
    return 1
  fi
  echo "Documents older than ${RETENTION_DAYS}d (workflow_run_started_at < ${cutoff}) in ${index}: ${match}"

  if [ "$DRY_RUN" = "true" ]; then
    echo "Dry run requested, not deleting."
    return 0
  fi

  if [ "$match" -eq 0 ]; then
    echo "Nothing to delete in ${index}."
    return 0
  fi

  # conflicts=proceed so a concurrent scrape rewriting a document does not abort
  # the whole delete. Documents skipped that way are picked up by the next run.
  echo "Deleting ${match} documents from ${index}..."
  local delete_response
  if ! delete_response=$(oscurl -XPOST \
    "${OPENSEARCH_URL}/${index}/_delete_by_query?conflicts=proceed&refresh=true" \
    -d "$query"); then
    echo "delete_by_query failed for ${index}: ${delete_response}" >&2
    return 1
  fi
  printf '%s' "$delete_response" | jq '{deleted, version_conflicts, failures}'

  local failures
  failures=$(printf '%s' "$delete_response" | jq -r '.failures | length')
  if [ "$failures" != "0" ]; then
    echo "delete_by_query reported failures for ${index}" >&2
    return 1
  fi

  # A delete only marks documents deleted, the disk they occupy is reclaimed
  # when the segments holding them are merged.
  echo "Reclaiming space in ${index} (force-merge only_expunge_deletes)..."
  if ! oscurl -XPOST "${OPENSEARCH_URL}/${index}/_forcemerge?only_expunge_deletes=true" >/dev/null; then
    echo "force-merge failed for ${index}" >&2
    return 1
  fi

  echo "Index ${index} after trim:"
  oscurl "${OPENSEARCH_URL}/_cat/indices/${index}?v&h=index,docs.count,docs.deleted,store.size" || true
}

rc=0
for index in "$@"; do
  if ! trim_index "$index"; then
    echo "failed to trim ${index}" >&2
    rc=1
  fi
done

exit "$rc"
