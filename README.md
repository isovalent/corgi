# CORGI 🐕

Cilium OpenseaRch GitHub Ingester is a connector for ingesting Cilium CI
data into OpenSearch.

## Workflow Runs

Use the `workflow runs` sub-command to download workflow runs for the target repository.
A bulk request is printed on stdout that can be given to OpenSearch for indexing.

Each document contains the following:

* Information regarding the workflow run.
* Jobs contained in the workflow
* Steps contained in the workflow
* Tests contained in the workflow, if a `cilium-junits` artifact is present.

The bulk request may be too large to send to OpenSearch in one request, so split it into smaller chunks.

## OpenSearch integration workflow

The [OpenSearch integration workflow](.github/workflows/opensearch-integration.yaml)
runs for pull requests. It starts the Compose OpenSearch service and Corgi
container, builds Corgi, and scrapes recent completed push runs from
`cilium/cilium` on `main`. The workflow exports the run and failure-rate bulk
files through the shared indexing action, then validates the indexed workflow,
job, step, test-suite, test-case, and failure-rate documents. It also inserts an
expired fixture, runs the retention script, and checks that the fixture was
deleted without changing the existing run documents.

### Run locally

Set the Compose inputs before starting the services. Use a GitHub token to avoid
anonymous API rate limits.

```shell
export OPENSEARCH_USER=admin
export OPENSEARCH_PASS='CorgiLocalTest1!'
export TARGET_REPOSITORY=cilium/cilium
export TARGET_BRANCH=main
export TARGET_RUNS_INDEX=corgi-local-runs
export TARGET_RATES_INDEX=corgi-local-rates
export GITHUB_TOKEN='your-github-token'
```

The example below fetches completed push runs from the last four hours and
indexes them in 200-line chunks. Corgi, `split`, and `curl` run in the Go
container, which waits for OpenSearch health and trusts the Compose-generated
CA.

```shell
docker compose up --detach corgi
docker compose exec --no-TTY corgi \
  bash ./.github/scripts/validate-integration-tests.sh build
docker compose exec --no-TTY corgi bash -ec '
  since=$(date -u -d "1 hours ago" "+%Y-%m-%dT%H")
  until=$(date -u "+%Y-%m-%dT%H")
  ./corgi workflow runs \
    --repository "$TARGET_REPOSITORY" \
    --branch "$TARGET_BRANCH" \
    --since "$since" \
    --until "$until" \
    --events push \
    --run-statuses completed \
    --index "$TARGET_RUNS_INDEX" > out.json
'

docker compose exec --no-TTY corgi bash -ec '
  mkdir -p /tmp/corgi-bulk-splits
  split -l 200 /workspace/out.json /tmp/corgi-bulk-splits/chunk-
  for part in /tmp/corgi-bulk-splits/chunk-*; do
    curl --silent --show-error --fail-with-body \
      --user "$OPENSEARCH_USER:$OPENSEARCH_PASS" \
      --header "Content-Type: application/x-ndjson" \
      --data-binary "@$part" \
      "$OPENSEARCH_URL/_bulk?refresh=wait_for" |
      jq --exit-status "(.errors == false)" >/dev/null
  done
'
```

The local example writes `out.json` in the repository directory. In the PR
workflow, the validation script writes `runs-results.json`; the workflow uses
[`.github/actions/index`](.github/actions/index/action.yaml) to split and upload
that file and the failure-rate bulk file before running the OpenSearch
validation and retention phases.
