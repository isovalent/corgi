# OpenSearch retention for the runs index

corgi scrapes GitHub Actions workflow runs into the `runs-oss` OpenSearch index.
With no retention, that index grows unbounded until the data node crosses its
flood-stage disk watermark (default 95%). OpenSearch then applies a
`read-only-allow-delete` block on the index and every bulk write is rejected
with `cluster_block_exception`, the failure seen in
[actions/runs/28184337085](https://github.com/isovalent/corgi/actions/runs/28184337085).

To prevent recurrence without renaming the index or changing how corgi writes, a
scheduled job trims documents older than the retention window. The index stays
a concrete `runs-oss`, so the scrape and rates pipelines are unchanged.

The enterprise `runs-cee` index is scraped by the workflows in
[isovalent/corgi-cee](https://github.com/isovalent/corgi-cee) and is trimmed by
the equivalent workflow there.

## Retention key

Every document corgi writes (`WorkflowRun`, `JobRun`, `StepRun`, `Testsuite`
and `Testcase`) embeds the parent workflow run, so all of them carry the
`workflow_run_started_at` field. A single `delete_by_query` on that field
therefore trims every document type cleanly, with no orphaned child docs.

## Automated trim

The [`.github/workflows/retention-runs.yaml`](../workflows/retention-runs.yaml)
workflow runs daily and invokes
[`.github/scripts/trim-runs-index.sh`](../scripts/trim-runs-index.sh), which for
each index given on the command line repeats
`POST <index>/_delete_by_query?conflicts=proceed&max_docs=<BATCH_SIZE>` for docs
with `workflow_run_started_at < now-<RETENTION_DAYS>d` (default 190d) until a
batch deletes fewer than `BATCH_SIZE` (default 50000, at least 1000) documents.
The proxy in front of OpenSearch returns a 504 for any request that runs past
300 seconds, and a typical day of about a million documents takes longer than
that to delete in a single request.

OpenSearch denies the CI user `indices:admin/refresh` and
`indices:monitor/settings/get`, so the script neither refreshes nor calls
`_cat/indices`. A role built on the `crud` action group gives exactly those
denials and also lacks `indices:admin/forcemerge`, so the script does not
force-merge either. A delete only marks documents as deleted. The merges that
the hourly scrapes trigger reclaim their disk, and the merge policy favours
segments whose share of deleted documents exceeds
`index.merge.policy.deletes_pct_allowed` (20% by default, 33% on OpenSearch
1.x). An admin can reclaim it sooner with the force-merge in the manual run
below.

Adjust the `indices`, `retention-days` and `dry-run` inputs to run it ad hoc, or
change the `env` defaults to trade history for disk. A failure on one index does
not stop the others.

The script can also be run locally, which is the easiest way to try a different
retention window before changing the workflow. `DRY_RUN=true` only counts the
matching documents and deletes nothing:

```
OPENSEARCH_URL=https://opensearch.example.com \
OPENSEARCH_USER=user OPENSEARCH_PASS=pass \
RETENTION_DAYS=190 DRY_RUN=true \
  ./.github/scripts/trim-runs-index.sh runs-oss
```

## Manual run (in a browser)

Open OpenSearch Dashboards, then Dev Tools, then Console (you are authenticated
via your Dashboards login, no credentials needed) and run the following. The
examples use `now-90d/d`; change the window to match your retention (the
automated workflow defaults to 190 days):

```
# How much disk / how many docs are we talking about?
GET _cat/indices/runs-oss?v&h=index,docs.count,store.size
GET runs-oss/_count
{ "query": { "range": { "workflow_run_started_at": { "lt": "now-90d/d" } } } }

# Delete old docs. conflicts=proceed so concurrent scrapes don't abort it.
POST runs-oss/_delete_by_query?conflicts=proceed&wait_for_completion=false
{ "query": { "range": { "workflow_run_started_at": { "lt": "now-90d/d" } } } }

# The previous call returns a task id; watch it to completion.
GET _tasks/<task-id-from-response>

# Reclaim disk from the deleted docs.
POST runs-oss/_forcemerge?only_expunge_deletes=true
```

## Recovering if the index is already read-only (flood-stage block)

If writes are currently rejected with `cluster_block_exception`:

```
# See which node is over the watermark and whether the block is set.
GET _cat/allocation?v&h=node,disk.percent,disk.avail
GET runs-oss/_settings/index.blocks.read_only_allow_delete

# Deletes ARE allowed under the read-only-allow-delete block, so free space
# first (this is the same trim query as above).
POST runs-oss/_delete_by_query?conflicts=proceed&wait_for_completion=false
{ "query": { "range": { "workflow_run_started_at": { "lt": "now-90d/d" } } } }
POST runs-oss/_forcemerge?only_expunge_deletes=true

# Clear the block with null (returns control to the disk monitor). On
# OpenSearch / ES >= 7.4 the block also auto-releases once disk drops below the
# HIGH watermark, so freeing space alone may suffice; this is a safety belt.
PUT runs-oss/_settings
{ "index.blocks.read_only_allow_delete": null }
```

Then re-run any failed scrape jobs via `workflow_dispatch`. Re-indexing is
idempotent because corgi computes deterministic document `_id`s
(`pkg/opensearch/bulk.go`), so backfilling overlapping windows overwrites rather
than duplicates.
