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
