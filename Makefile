GOPATH      := $(shell go env GOPATH)

BIN_DIR             ?= $(shell pwd)/bin
BIN_NAME            ?= ssl_exporter$(shell go env GOEXE)
DOCKER_IMAGE_NAME   ?= ssl-exporter
DOCKER_IMAGE_TAG    ?= $(subst /,-,$(shell git rev-parse --abbrev-ref HEAD))
HELM_DOCS_VERSION   ?= v1.14.2
MANIFEST_DIR        ?= deploy/manifests
MANIFEST_NAMESPACE  ?= ssl-exporter

# Race detector is only supported on amd64.
RACE := $(shell test $$(go env GOARCH) != "amd64" || (echo "-race"))

export APP_HOST              ?= $(shell hostname)
export APP_BRANCH            ?= $(shell git describe --all --contains --dirty HEAD)
export APP_USER              := $(shell id -u --name)
export APP_DOCKER_IMAGE_NAME := piotrkochan/$(DOCKER_IMAGE_NAME)

all: clean format vet build test

style:
	@echo ">> checking code style"
	@! gofmt -s -d . | grep '^'

test:
	@echo ">> running tests"
	go test -short -v $(RACE) ./...

cover:
	@echo ">> running tests with coverage"
	go test -short $(RACE) -coverprofile=coverage.txt -covermode=atomic ./...

format:
	@echo ">> formatting code"
	@gofmt -s -w .

vet:
	@echo ">> vetting code"
	@go vet $(pkgs)

build:
	@echo ">> building binary"
	@CGO_ENABLED=0 go build -v \
		-ldflags "-X github.com/prometheus/common/version.Version=dev \
		-X github.com/prometheus/common/version.Revision=$(shell git rev-parse HEAD) \
		-X github.com/prometheus/common/version.Branch=$(APP_BRANCH) \
		-X github.com/prometheus/common/version.BuildUser=$(APP_USER)@$(APP_HOST) \
		-X github.com/prometheus/common/version.BuildDate=$(shell date '+%Y%m%d-%H:%M:%S') \
		" \
		-o $(BIN_NAME) .

docker:
	@echo ">> building docker image"
	@docker build -t "$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)" -f Dockerfile.local .

$(GOPATH)/bin/goreleaser:
	@go install github.com/goreleaser/goreleaser/v2@v2.16.0

snapshot: $(GOPATH)/bin/goreleaser
	@echo ">> building snapshot"
	@$(GOPATH)/bin/goreleaser release --snapshot --clean --skip=sign,validate,publish

release: $(GOPATH)/bin/goreleaser
	@$(GOPATH)/bin/goreleaser release --clean

clean:
	@echo ">> removing build artifacts"
	@rm -Rf $(BIN_DIR)
	@rm -Rf $(BIN_NAME)

$(GOPATH)/bin/helm-docs:
	@go install github.com/norwoodj/helm-docs/cmd/helm-docs@$(HELM_DOCS_VERSION)

helm-docs: $(GOPATH)/bin/helm-docs
	@echo ">> generating helm chart docs"
	@$(GOPATH)/bin/helm-docs --chart-search-root charts

helm-test:
	@echo ">> linting helm chart"
	@helm lint charts/ssl-exporter/
	@echo ">> running helm unit tests"
	@helm unittest charts/ssl-exporter/

manifests:
	@echo ">> generating static Kubernetes manifests"
	@mkdir -p $(MANIFEST_DIR)
	@printf "# Generated from charts/ssl-exporter. Do not edit by hand.\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: $(MANIFEST_NAMESPACE)\n" > $(MANIFEST_DIR)/ssl-exporter.yaml
	@helm template ssl-exporter charts/ssl-exporter --namespace $(MANIFEST_NAMESPACE) | sed '/^[[:space:]]*helm.sh\/chart: /d;/^[[:space:]]*app.kubernetes.io\/managed-by: Helm/d' >> $(MANIFEST_DIR)/ssl-exporter.yaml
	@printf "# Generated from charts/ssl-exporter. Do not edit by hand.\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: $(MANIFEST_NAMESPACE)\n" > $(MANIFEST_DIR)/ssl-exporter-kubernetes-secrets.yaml
	@helm template ssl-exporter charts/ssl-exporter --namespace $(MANIFEST_NAMESPACE) --set rbac.create=true --set serviceAccount.automountServiceAccountToken=true | sed '/^[[:space:]]*helm.sh\/chart: /d;/^[[:space:]]*app.kubernetes.io\/managed-by: Helm/d' >> $(MANIFEST_DIR)/ssl-exporter-kubernetes-secrets.yaml

e2e:
	@echo ">> running e2e tests"
	@chmod +x e2e/run.sh
	@e2e/run.sh

.PHONY: all style test cover format vet build docker snapshot release clean e2e helm-docs helm-test manifests
