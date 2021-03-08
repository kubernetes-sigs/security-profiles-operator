# Copyright 2020 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GO ?= go

CONTROLLER_GEN_CMD := $(GO) run -tags generate sigs.k8s.io/controller-tools/cmd/controller-gen

PROJECT := security-profiles-operator
BUILD_DIR := build

DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date -u "$(DATE_FMT)")
endif

GIT_COMMIT := $(shell git rev-parse HEAD 2> /dev/null || echo unknown)
GIT_TREE_STATE := $(if $(shell git status --porcelain --untracked-files=no),dirty,clean)
VERSION := $(shell cat VERSION)

ifneq ($(shell uname -s), Darwin)
BUILDTAGS := netgo osusergo seccomp
else
BUILDTAGS := netgo osusergo
endif

ifneq ($(shell uname -s), Darwin)
LINT_BUILDTAGS := e2e,netgo,osusergo,seccomp,-tools
else
LINT_BUILDTAGS := e2e,netgo,osusergo,-tools
endif

export CGO_ENABLED=1

BUILD_FILES := $(shell find . -type f -name '*.go' -or -name '*.mod' -or -name '*.sum' -not -name '*_test.go')
export GOFLAGS?=-mod=vendor
GO_PROJECT := sigs.k8s.io/$(PROJECT)
LDVARS := \
	-X $(GO_PROJECT)/internal/pkg/version.buildDate=$(BUILD_DATE) \
	-X $(GO_PROJECT)/internal/pkg/version.gitCommit=$(GIT_COMMIT) \
	-X $(GO_PROJECT)/internal/pkg/version.gitTreeState=$(GIT_TREE_STATE) \
	-X $(GO_PROJECT)/internal/pkg/version.version=$(VERSION)
LINKMODE_EXTERNAL ?= yes
ifeq ($(LINKMODE_EXTERNAL), yes)
  LDFLAGS := -s -w -linkmode external -extldflags "-static" $(LDVARS)
else
  LDFLAGS := -s -w -extldflags "-static" $(LDVARS)
endif

export CONTAINER_RUNTIME ?= $(if $(shell which podman 2>/dev/null),podman,docker)

ifeq ($(CONTAINER_RUNTIME), podman)
    LOGIN_PUSH_OPTS="--tls-verify=false"
else ifeq ($(CONTAINER_RUNTIME), docker)
    LOGIN_PUSH_OPTS=
endif

IMAGE ?= $(PROJECT):latest

CRD_OPTIONS ?= "crd:crdVersions=v1"

GOLANGCI_LINT_VERSION = v1.38.0
REPO_INFRA_VERSION = v0.1.2

export E2E_CLUSTER_TYPE ?= kind

DOCKERFILE ?= Dockerfile

# Utility targets

all: $(BUILD_DIR)/$(PROJECT) ## Build the security-profiles-operator binary

.PHONY: help
help:  ## Display this help
	@awk \
		-v "col=${COLOR}" -v "nocol=${NOCOLOR}" \
		' \
			BEGIN { \
				FS = ":.*##" ; \
				printf "Available targets:\n"; \
			} \
			/^[a-zA-Z0-9_-]+:.*?##/ { \
				printf "  %s%-25s%s %s\n", col, $$1, nocol, $$2 \
			} \
			/^##@/ { \
				printf "\n%s%s%s\n", col, substr($$0, 5), nocol \
			} \
		' $(MAKEFILE_LIST)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(PROJECT): $(BUILD_DIR) $(BUILD_FILES)
	$(GO) build -ldflags '$(LDFLAGS)' -tags '$(BUILDTAGS)' -o $@ ./cmd/security-profiles-operator

.PHONY: clean
clean: ## Clean the build directory
	rm -rf $(BUILD_DIR)

$(BUILD_DIR)/kustomize: $(BUILD_DIR)
	export \
		VERSION=4.0.1 \
		URL=https://raw.githubusercontent.com/kubernetes-sigs/kustomize && \
	curl -sfL $$URL/master/hack/install_kustomize.sh \
		| bash -s $$VERSION $(PWD)/$(BUILD_DIR)

.PHONY: deployments
deployments: $(BUILD_DIR)/kustomize manifests generate ## Generate the deployment files with kustomize
	$(BUILD_DIR)/kustomize build --reorder=none deploy/overlays/cluster -o deploy/operator.yaml
	$(BUILD_DIR)/kustomize build --reorder=none deploy/overlays/namespaced -o deploy/namespace-operator.yaml
	$(BUILD_DIR)/kustomize build --reorder=none deploy/base/webhook -o deploy/webhook.yaml

.PHONY: image
image: ## Build the container image
	$(CONTAINER_RUNTIME) build -f $(DOCKERFILE) --build-arg version=$(VERSION) -t $(IMAGE) .

.PHONY: image-arm64
image-arm64: ## Build the container image for arm64
	$(CONTAINER_RUNTIME) build -f $(DOCKERFILE) \
		--build-arg version=$(VERSION) \
		--build-arg target=nix/default-arm64.nix \
		-t $(IMAGE) .

.PHONY: image-cross
image-cross: ## Build and push the container image manifest
	hack/image-cross.sh

.PHONY: nix
nix: ## Build the binary via nix for the current system
	nix-build nix

.PHONY: nix-arm64
nix-arm64: ## Build the binary via nix for arm64
	nix-build nix/default-arm64.nix

.PHONY: update-nixpkgs
update-nixpkgs: ## Update the pinned nixpkgs to the latest master
	@nix run -f channel:nixpkgs-unstable nix-prefetch-git -c nix-prefetch-git \
		--no-deepClone https://github.com/nixos/nixpkgs > nix/nixpkgs.json

.PHONY: update-go-mod
update-go-mod: ## Cleanup, vendor and verify go modules
	export GO111MODULE=on && \
		$(GO) mod tidy && \
		$(GO) mod vendor && \
		$(GO) mod verify

.PHONY: update-mocks
update-mocks: ## Update all generated mocks
	go generate ./...
	for f in $(shell find . -path ./vendor -prune -false -o -name fake_*.go); do \
		cp hack/boilerplate/boilerplate.go.txt tmp ;\
		sed -i.bak -e 's/YEAR/'$(shell date +"%Y")'/g' -- tmp && rm -- tmp.bak ;\
		cat $$f >> tmp ;\
		mv tmp $$f ;\
	done

.PHONY: vagrant-up
vagrant-up: ## Boot the vagrant based test VM
	if [ ! -f image.tar ]; then \
		make image IMAGE=$(IMAGE) && \
		$(CONTAINER_RUNTIME) save -o image.tar $(IMAGE); \
	fi
	ln -sf hack/ci/Vagrantfile .
	# Retry in case provisioning failed because of some temporarily unavailable
	# remote resource (like the VM image)
	vagrant up || vagrant up || vagrant up

# Verification targets

.PHONY: verify
verify: verify-boilerplate verify-go-mod verify-go-lint verify-deployments ## Run all verification targets

.PHONY: verify-boilerplate
verify-boilerplate: $(BUILD_DIR)/verify_boilerplate.py ## Verify the boilerplate headers for all files
	$(BUILD_DIR)/verify_boilerplate.py --boilerplate-dir hack/boilerplate

$(BUILD_DIR)/verify_boilerplate.py: $(BUILD_DIR)
	curl -sfL https://raw.githubusercontent.com/kubernetes/repo-infra/$(REPO_INFRA_VERSION)/hack/verify_boilerplate.py \
		-o $(BUILD_DIR)/verify_boilerplate.py
	chmod +x $(BUILD_DIR)/verify_boilerplate.py

.PHONY: verify-go-mod
verify-go-mod: update-go-mod ## Verify the go modules
	hack/tree-status

.PHONY: verify-deployments
verify-deployments: deployments ## Verify the generated deployments
	hack/tree-status

.PHONY: verify-go-lint
verify-go-lint: $(BUILD_DIR)/golangci-lint ## Verify the golang code by linting
	$(BUILD_DIR)/golangci-lint run --build-tags $(LINT_BUILDTAGS)

$(BUILD_DIR)/golangci-lint:
	export \
		VERSION=$(GOLANGCI_LINT_VERSION) \
		URL=https://raw.githubusercontent.com/golangci/golangci-lint \
		BINDIR=$(BUILD_DIR) && \
	curl -sfL $$URL/$$VERSION/install.sh | sh -s $$VERSION
	$(BUILD_DIR)/golangci-lint version
	$(BUILD_DIR)/golangci-lint linters


# Test targets

.PHONY: test-unit
test-unit: $(BUILD_DIR) ## Run the unit tests
	# remove all coverage files if exists
	rm -rf *.out
	# run the go tests and gen the file coverage-all used to do the integration with coverrals.io
	$(GO) test -ldflags '$(LDVARS)' -tags '$(BUILDTAGS)' -race -v -test.coverprofile=$(BUILD_DIR)/coverage.out ./internal/...
	$(GO) tool cover -html $(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

.PHONY: test-e2e
test-e2e: ## Run the end-to-end tests
	$(GO) test -parallel 1 -timeout 80m -count=1 ./test/... -v

# Generate CRD manifests
manifests:
	$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths="./api/spod/..." output:crd:stdout > deploy/base/crd.yaml
	$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths="./api/secprofnodestatus/..." output:crd:stdout >> deploy/base/crd.yaml
	$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths="./api/seccompprofile/..." output:crd:stdout >> deploy/base/crd.yaml
	$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths="./api/selinuxpolicy/..." output:crd:stdout >> deploy/base/crd.yaml
	$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths="./api/profilebinding/..." output:crd:stdout > deploy/base/webhook/crd-binding.yaml
	$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths="./api/profilerecording/..." output:crd:stdout > deploy/base/webhook/crd-recording.yaml

# Generate deepcopy code
generate:
	$(CONTROLLER_GEN_CMD) object:headerFile="hack/boilerplate/boilerplate.go.txt",year=$(shell date -u "+%Y") paths="./..."
	$(CONTROLLER_GEN_CMD) rbac:roleName=security-profiles-operator paths="./internal/pkg/manager/..." output:rbac:stdout > deploy/base/role.yaml
	$(CONTROLLER_GEN_CMD) rbac:roleName=spod paths="./internal/pkg/daemon/..." output:rbac:stdout >> deploy/base/role.yaml
	$(CONTROLLER_GEN_CMD) rbac:roleName=spo-webhook paths="./internal/pkg/webhooks/..." output:rbac:stdout > deploy/base/webhook/role.yaml

## OpenShift-only
## These targets are meant to make development in OpenShift easier.

.PHONY: openshift-user
openshift-user:
ifeq ($(shell oc whoami 2> /dev/null),kube:admin)
	$(eval OPENSHIFT_USER = kubeadmin)
else
	$(eval OPENSHIFT_USER = $(shell oc whoami))
endif

.PHONY: set-openshift-image-params
set-openshift-image-params:
	$(eval DOCKERFILE = Dockerfile.ubi)

.PHONY: push-openshift-dev
push-openshift-dev: set-openshift-image-params openshift-user image
	@echo "Exposing the default route to the image registry"
	@oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{"spec":{"defaultRoute":true}}' --type=merge
	@echo "Pushing image $(IMAGE) to the image registry"
	@IMAGE_REGISTRY_HOST=$$(oc get route default-route -n openshift-image-registry --template='{{ .spec.host }}'); \
		$(CONTAINER_RUNTIME) login $(LOGIN_PUSH_OPTS) -u $(OPENSHIFT_USER) -p $(shell oc whoami -t) $${IMAGE_REGISTRY_HOST}; \
		$(CONTAINER_RUNTIME) push $(LOGIN_PUSH_OPTS) localhost/$(IMAGE) $${IMAGE_REGISTRY_HOST}/openshift/$(IMAGE)

.PHONY: do-deploy-openshift-dev
do-deploy-openshift-dev: $(BUILD_DIR)/kustomize
	@echo "Deploying cert-manager"
	oc apply -f https://github.com/jetstack/cert-manager/releases/download/v1.1.0/cert-manager.yaml
	oc wait --for=condition=Ready pod -lapp.kubernetes.io/instance=cert-manager -ncert-manager
	@echo "Building custom operator.yaml"
	$(BUILD_DIR)/kustomize build --reorder=none deploy/overlays/openshift-dev -o deploy/operator.yaml
	sed -i 's/enableSelinux: false/enableSelinux: true/' deploy/operator.yaml
	@echo "Deploying"
	oc apply -f deploy/operator.yaml
	@echo "Setting triggers to track image"
	oc set triggers -n security-profiles-operator deployment/security-profiles-operator --from-image openshift/security-profiles-operator:latest -c security-profiles-operator
	@echo "Resetting operator.yaml"
	git checkout deploy/operator.yaml

# Deploy for development into OpenShift
.PHONY: deploy-openshift-dev
deploy-openshift-dev: push-openshift-dev do-deploy-openshift-dev
