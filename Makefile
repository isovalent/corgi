GO ?= go
GO_BUILD_FLAGS ?=
GO_LINT_FLAGS := --modules-download-mode=vendor --verbose
DOCKER_BUILD_FLAGS ?=
IMAGE_TAG ?= latest

.PHONY: all
all: test

include Makefile.OpenSearch

corgi: $(shell find . -iname "*.go") # Build the main binary
	CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) \
			    -mod=vendor \
			    -o $@ .

.PHONY: build # Build the main binary
build: corgi

.PHONY: test
test: build # Build and run the tests
	$(GO) test -mod=vendor ./...

.PHONY: lint
lint:
	golangci-lint run $(GO_LINT_FLAGS)

.PHONY: lint-fix
lint-fix:
	golangci-lint run $(GO_LINT_FLAGS) --fix

.PHONY: clean
clean: # Clean the local generated artifacts
	rm -fr -- corgi

.PHONY: web-report
web-report: # Generate reports and serve them via Jekyll
	@TMP_BASE=$${WEB_REPORT_TMPDIR:-/tmp}; \
	REPORT_TMP=$${REPORT_TMP:-$$(mktemp -d "$$TMP_BASE/corgi_pages_XXXXXX")}; \
	command -v jekyll >/dev/null 2>&1 || { echo "jekyll is required in PATH" >&2; exit 1; }; \
	echo "Using report output: $$REPORT_TMP"; \
	if [ "$${WEB_REPORT_SKIP_GENERATION:-0}" != "1" ]; then \
		$(GO) run . report --output-dir "$$REPORT_TMP"; \
	else \
		echo "Skipping report generation (WEB_REPORT_SKIP_GENERATION=1)"; \
	fi; \
	if [ -f "$$REPORT_TMP/Home.md" ] && [ ! -f "$$REPORT_TMP/README.md" ]; then \
		cp "$$REPORT_TMP/Home.md" "$$REPORT_TMP/README.md"; \
	fi; \
	LOCAL_CFG="$$REPORT_TMP/_config.local.yml"; \
	printf '%s\n' \
		'title: OSS CI Health Reports' \
		'markdown: kramdown' \
		'kramdown:' \
		'  input: GFM' \
		'plugins:' \
		'  - jekyll-relative-links' \
		'  - jekyll-optional-front-matter' \
		'  - jekyll-readme-index' \
		'relative_links:' \
		'  enabled: true' \
		'  collections: true' \
		'readme_index:' \
		'  enabled: true' > "$$LOCAL_CFG"; \
	if [ -f "$$REPORT_TMP/_config.yml" ]; then \
		CONFIG_FILES="$$REPORT_TMP/_config.yml,$$LOCAL_CFG"; \
	else \
		CONFIG_FILES="$$LOCAL_CFG"; \
	fi; \
	echo "Starting Jekyll at http://127.0.0.1:4000"; \
	jekyll serve --host 127.0.0.1 --port 4000 --source "$$REPORT_TMP" --destination "$$REPORT_TMP/_site" --config "$$CONFIG_FILES"

.PHONY: kube-test
kube-test: opensearch-values.yaml # Set up a kube environment with opensearch
	kubectl create namespace corgi-test \
		--dry-run=client -o yaml \
	| kubectl apply -f -
	helm repo add opensearch https://opensearch-project.github.io/helm-charts/
	helm repo update
	helm upgrade opensearch opensearch/opensearch \
		--install \
		--namespace corgi-test \
		--values opensearch-values.yaml
	helm upgrade opensearch-dashboards opensearch/opensearch-dashboards \
		--install \
		--namespace corgi-test
	>&2 echo
	>&2 echo "You can use 'make kube-port-forward' to expose opensearch ports locally"

.PHONY: kube-port-forward
kube-port-forward: opensearch-ready # Port-forward access to opensearch into the host
	-@pkill -f 'port-forward opensearch.*corgi-test'
	$(eval KOS_SERV=$(shell kubectl get pods --namespace corgi-test -l "app.kubernetes.io/name=opensearch" -o jsonpath="{.items[0].metadata.name}"))
	$(eval KOS_SERV_PORT=$(shell kubectl get pod --namespace corgi-test $(KOS_SERV) -o jsonpath="{.spec.containers[0].ports[0].containerPort}"))
	kubectl port-forward $(KOS_SERV) 9200:$(KOS_SERV_PORT) \
		--namespace=corgi-test \
		--address 127.0.0.1 \
		&
	$(eval KOS_DASH=$(shell kubectl get pods --namespace corgi-test -l "app.kubernetes.io/name=opensearch-dashboards" -o jsonpath="{.items[0].metadata.name}"))
	$(eval KOS_DASH_PORT=$(shell kubectl get pod --namespace corgi-test $(KOS_DASH) -o jsonpath="{.spec.containers[0].ports[0].containerPort}"))
	kubectl port-forward $(KOS_DASH) 5601:$(KOS_DASH_PORT) \
		--namespace=corgi-test \
		--address 127.0.0.1 \
		&
