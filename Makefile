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

GOLANGCI_LINT_VERSION = v1.62.0
REPO_INFRA_VERSION = v0.2.5
KUSTOMIZE_VERSION = 5.5.0
OPERATOR_SDK_VERSION ?= v1.37.0
ZEITGEIST_VERSION = v0.5.4
MDTOC_VERSION = v1.4.0
CI_IMAGE ?= golang:1.23

CONTROLLER_GEN_CMD := CGO_LDFLAGS= $(GO) run $(BUILD_FLAGS) -tags generate sigs.k8s.io/controller-tools/cmd/controller-gen

PROJECT := security-profiles-operator
CLI_BINARY := spoc
BUILD_DIR := build

APPARMOR_ENABLED ?= 1
BPF_ENABLED ?= 1

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_PATH := internal/pkg/daemon/bpfrecorder/bpf
ARCH ?= $(shell uname -m | \
	sed 's/x86_64/amd64/' | \
	sed 's/aarch64/arm64/' | \
	sed 's/ppc64le/powerpc/' | \
	sed 's/mips.*/mips/')
INCLUDES := -I$(BUILD_DIR)

DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date -u "$(DATE_FMT)")
endif

VERSION := $(shell cat VERSION)

ifneq ($(shell uname -s), Darwin)
BUILDTAGS := netgo osusergo seccomp
CGO_LDFLAGS=-lseccomp
else
BUILDTAGS := netgo osusergo
APPARMOR_ENABLED = 0
BPF_ENABLED = 0
endif

ifneq ($(shell uname -s), Darwin)
LINT_BUILDTAGS := e2e,netgo,osusergo,seccomp,-tools
else
LINT_BUILDTAGS := e2e,netgo,osusergo,-tools
endif

ifneq ($(shell uname -s), Darwin)
OS := linux
SED ?= sed -i
else
OS := darwin
SED ?= sed -i ''
endif

ifeq ($(APPARMOR_ENABLED), 1)
BUILDTAGS := $(BUILDTAGS) apparmor
LINT_BUILDTAGS := $(LINT_BUILDTAGS),apparmor
endif

ifeq ($(BPF_ENABLED), 1)
CGO_LDFLAGS := $(CGO_LDFLAGS) -lelf -lz -lbpf -lzstd
else
BUILDTAGS := $(BUILDTAGS) no_bpf
LINT_BUILDTAGS := $(LINT_BUILDTAGS),no_bpf
endif

export CGO_LDFLAGS
export CGO_ENABLED=1

BUILD_FILES := $(shell find . -type f -name '*.go' -or -name '*.mod' -or -name '*.sum' -not -name '*_test.go')
export GOFLAGS?=-mod=vendor
GO_PROJECT := sigs.k8s.io/$(PROJECT)
LDVARS := \
	-X $(GO_PROJECT)/internal/pkg/version.buildDate=$(BUILD_DATE) \
	-X $(GO_PROJECT)/internal/pkg/version.version=$(VERSION)
STATIC_LINK ?= yes
ifeq ($(STATIC_LINK), yes)
  EXTLDFLAGS := -extldflags "-static"
else
  EXTLDFLAGS :=
endif

LINKMODE_EXTERNAL ?= yes
ifeq ($(LINKMODE_EXTERNAL), yes)
  LDFLAGS := -s -w -linkmode external $(EXTLDFLAGS) $(LDVARS)
else
  LDFLAGS := -s -w $(EXTLDFLAGS) $(LDVARS)
endif

export CONTAINER_RUNTIME ?= $(if $(shell which podman 2>/dev/null),podman,docker)

ifeq ($(CONTAINER_RUNTIME), podman)
    LOGIN_PUSH_OPTS="--tls-verify=false"
else ifeq ($(CONTAINER_RUNTIME), docker)
    LOGIN_PUSH_OPTS=
endif

IMAGE ?= $(PROJECT):latest

CRD_OPTIONS ?= "crd:crdVersions=v1"

export E2E_CLUSTER_TYPE ?= kind

DOCKERFILE ?= Dockerfile

# Utility targets

all: $(BUILD_DIR)/$(PROJECT) $(BUILD_DIR)/$(CLI_BINARY) ## Build the project binaries

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

define go-build-spo
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -tags '$(BUILDTAGS)' -o $@ ./cmd/$(1)
endef

$(BUILD_DIR)/$(PROJECT): $(BUILD_DIR) $(BUILD_FILES)
	$(call go-build-spo,$(PROJECT))

$(BUILD_DIR)/$(CLI_BINARY): $(BUILD_DIR) $(BUILD_FILES)
	$(call go-build-spo,$(CLI_BINARY))

.PHONY: clean
clean: ## Clean the build directory
	rm -rf $(BUILD_DIR)

.PHONY: $(BUILD_DIR)/kustomize
$(BUILD_DIR)/kustomize: $(BUILD_DIR)
	if [ ! -f $@ ]; then \
		export URL=https://raw.githubusercontent.com/kubernetes-sigs/kustomize && \
		curl -sfL $$URL/master/hack/install_kustomize.sh \
			| bash -s $(KUSTOMIZE_VERSION) $(PWD)/$(BUILD_DIR); \
	fi

$(BUILD_DIR)/kubernetes-split-yaml: $(BUILD_DIR)
	$(call go-build,./vendor/github.com/mogensen/kubernetes-split-yaml)

.PHONY: deployments
deployments: $(BUILD_DIR)/kustomize manifests generate ## Generate the deployment files with kustomize
	$(BUILD_DIR)/kustomize build deploy/overlays/cluster -o deploy/operator.yaml
	$(BUILD_DIR)/kustomize build deploy/overlays/namespaced -o deploy/namespace-operator.yaml
	$(BUILD_DIR)/kustomize build deploy/overlays/openshift-dev -o deploy/openshift-dev.yaml
	$(BUILD_DIR)/kustomize build deploy/overlays/openshift-downstream -o deploy/openshift-downstream.yaml
	$(BUILD_DIR)/kustomize build deploy/overlays/helm -o deploy/helm/templates/static-resources.yaml
	$(BUILD_DIR)/kustomize build deploy/base-crds -o deploy/helm/crds/crds.yaml
	$(BUILD_DIR)/kustomize build deploy/overlays/webhook -o deploy/webhook-operator.yaml

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

define nix-build-to
	nix-build nix/default-$(1).nix
	mkdir -p $(BUILD_DIR)/$(1)
	cp -f result/* $(BUILD_DIR)/$(1)
endef

.PHONY: nix
nix: nix-amd64 nix-arm64 ## Build all binaries via nix and create a build.tar.gz
	tar cvfz build.tar.gz -C $(BUILD_DIR) amd64 arm64

.PHONY: nix-amd64
nix-amd64: ## Build the binaries via nix for amd64
	$(call nix-build-to,amd64)

.PHONY: nix-arm64
nix-arm64: ## Build the binaries via nix for arm64
	$(call nix-build-to,arm64)

define nix-build-sign-spoc-to
	nix-build nix/default-spoc-$(1).nix
	cp -f result/spoc $(BUILD_DIR)/spoc.$(1)
	cosign sign-blob -y \
		$(BUILD_DIR)/spoc.$(1) \
		--output-signature $(BUILD_DIR)/spoc.$(1).sig \
		--output-certificate $(BUILD_DIR)/spoc.$(1).cert
	cd $(BUILD_DIR) && sha512sum spoc.$(1) > spoc.$(1).sha512
endef

.PHONY: nix-spoc
nix-spoc: nix-spoc-amd64 nix-spoc-arm64 ## Build all spoc binaries via nix.
	bom version
	bom generate \
		-l Apache-2.0 \
		--name spoc \
		-d $(BUILD_DIR) \
		-o $(BUILD_DIR)/spoc.spdx
	cosign sign-blob -y \
		$(BUILD_DIR)/spoc.spdx \
		--output-signature $(BUILD_DIR)/spoc.spdx.sig \
		--output-certificate $(BUILD_DIR)/spoc.spdx.cert

.PHONY: nix-spoc-amd64
nix-spoc-amd64: $(BUILD_DIR) ## Build and sign the spoc binary via nix for amd64
	$(call nix-build-sign-spoc-to,amd64)

.PHONY: nix-spoc-arm64
nix-spoc-arm64: $(BUILD_DIR) ## Build and sign the spoc binary via nix for arm64
	$(call nix-build-sign-spoc-to,arm64)

.PHONY: update-nixpkgs
update-nixpkgs: ## Update the pinned nixpkgs to the latest master
	@nix run -f channel:nixpkgs-unstable nix-prefetch-git -- \
		--no-deepClone https://github.com/nixos/nixpkgs > nix/nixpkgs.json

.PHONY: update-go-mod
update-go-mod: ## Cleanup, vendor and verify go modules
	export GO111MODULE=on && \
		$(GO) mod tidy && \
		$(GO) mod vendor && \
		$(GO) mod verify

.PHONY: update-mocks
update-mocks: ## Update all generated mocks
	$(GO) generate ./...

define go-build
	CGO_LDFLAGS= $(GO) build -o $(BUILD_DIR)/$(shell basename $(1)) $(1)
	@echo > /dev/null
endef

$(BUILD_DIR)/protoc-gen-go-grpc: $(BUILD_DIR)
	$(call go-build,./vendor/google.golang.org/grpc/cmd/protoc-gen-go-grpc)

$(BUILD_DIR)/protoc-gen-go: $(BUILD_DIR)
	$(call go-build,./vendor/google.golang.org/protobuf/cmd/protoc-gen-go)

.PHONY: update-proto
update-proto: $(BUILD_DIR)/protoc-gen-go $(BUILD_DIR)/protoc-gen-go-grpc ## Update GRPC server protocol definitions
	for PROTO in \
		api/grpc/metrics \
		api/grpc/enricher \
		api/grpc/bpfrecorder \
	; do \
	PATH=$(BUILD_DIR):$$PATH \
		 protoc \
			--go_out=. \
			--go_opt=paths=source_relative \
			--go-grpc_out=. \
			--go-grpc_opt=paths=source_relative \
			$$PROTO/api.proto ;\
	done

define vagrant-up
	if [ ! -f image.tar ] && [ $(2) = build ]; then \
		make image IMAGE=$(IMAGE) && \
		$(CONTAINER_RUNTIME) save -o image.tar $(IMAGE); \
	fi
	ln -sf hack/ci/Vagrantfile-$(1) Vagrantfile
	# Retry in case provisioning failed because of some temporarily unavailable
	# remote resource (like the VM image)
	vagrant up
endef

.PHONY: vagrant-up-fedora
vagrant-up-fedora: ## Boot the Vagrant Fedora based test VM
	$(call vagrant-up,fedora,build)

.PHONY: vagrant-up-ubuntu
vagrant-up-ubuntu: ## Boot the Vagrant Ubuntu based test VM
	$(call vagrant-up,ubuntu,build)

.PHONY: vagrant-up-debian
vagrant-up-debian: ## Boot the Vagrant Debian based test VM
	$(call vagrant-up,debian,build)

.PHONY: vagrant-up-flatcar
vagrant-up-flatcar: ## Boot the Vagrant Flatcar based test VM
	$(call vagrant-up,flatcar,build)

$(BUILD_DIR)/mdtoc: $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/mdtoc \
		https://storage.googleapis.com/k8s-artifacts-sig-release/kubernetes-sigs/mdtoc/$(MDTOC_VERSION)/mdtoc-$(ARCH)-$(OS)
	chmod +x $(BUILD_DIR)/mdtoc

.PHONY: update-toc
update-toc: $(BUILD_DIR)/mdtoc ## Update the table of contents for the documentation
	git grep --name-only '<!-- toc -->' | grep -v Makefile | xargs $(BUILD_DIR)/mdtoc -i

$(BUILD_DIR)/recorder.bpf.o: $(BUILD_DIR) ## Build the BPF module
	$(CLANG) -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		$(CFLAGS) \
		-I ./internal/pkg/daemon/bpfrecorder/vmlinux/$(ARCH) \
		-c $(BPF_PATH)/recorder.bpf.c \
		-o $@
	$(LLVM_STRIP) -g $@

.PHONY: update-vmlinux
update-vmlinux: ## Generate the vmlinux.h required for building the BPF modules.
	./hack/update-vmlinux

.PHONY: update-btf
update-btf: update-bpf ## Build and update all generated BTF code for supported kernels
	./hack/update-btf

.PHONY: update-bpf
update-bpf: $(BUILD_DIR) ## Build and update all generated BPF code with nix
	for arch in amd64 arm64; do \
		nix-build nix/default-bpf-$$arch.nix ;\
		cp -f result/recorder.bpf.o $(BUILD_DIR)/recorder.bpf.o.$$arch ;\
	done
	chmod 0644 $(BUILD_DIR)/recorder.bpf.o.*
	$(GO) run ./internal/pkg/daemon/bpfrecorder/generate

# Verification targets

.PHONY: verify
verify: verify-boilerplate verify-go-mod verify-go-lint verify-deployments verify-dependencies verify-toc verify-mocks verify-format ## Run all verification targets

.PHONY: verify-in-a-container
verify-in-a-container: ## Run all verification targets in a container
	export WORKDIR=/go/src/sigs.k8s.io/security-profiles-operator && \
	$(CONTAINER_RUNTIME) run -it \
		-v $(shell pwd):$$WORKDIR \
		-v $(shell go env GOCACHE):/root/.cache/go-build \
		-v $(shell go env GOMODCACHE):/go/pkg/mod \
		-e GOCACHE=/root/.cache/go-build \
		-e GOMODCACHE=/go/pkg/mod \
		-w $$WORKDIR \
		$(CI_IMAGE) \
		hack/pull-security-profiles-operator-verify

.PHONY: verify-boilerplate
verify-boilerplate: $(BUILD_DIR)/verify_boilerplate.py ## Verify the boilerplate headers for all files
	$(BUILD_DIR)/verify_boilerplate.py \
		--boilerplate-dir hack/boilerplate \
		--skip api/grpc/metrics/api_grpc.pb.go \
		--skip api/grpc/enricher/api_grpc.pb.go \
		--skip api/grpc/bpfrecorder/api_grpc.pb.go \
		--skip api/grpc/bpfrecorder/api.pb.go \
		--skip api/grpc/enricher/api.pb.go \
		--skip api/grpc/metrics/api.pb.go \
		--skip api/apparmorprofile/v1alpha1/zz_generated.deepcopy.go \
		--skip api/profilebinding/v1alpha1/zz_generated.deepcopy.go \
		--skip api/profilerecording/v1alpha1/zz_generated.deepcopy.go \
		--skip api/seccompprofile/v1beta1/zz_generated.deepcopy.go \
		--skip api/secprofnodestatus/v1alpha1/zz_generated.deepcopy.go \
		--skip api/selinuxprofile/v1alpha2/zz_generated.deepcopy.go \
		--skip api/spod/v1alpha1/zz_generated.deepcopy.go \
		--skip internal/pkg/daemon/bpfrecorder/bpfrecorderfakes/fake_impl.go \
		--skip internal/pkg/daemon/enricher/enricherfakes/fake_impl.go \
		--skip internal/pkg/daemon/metrics/metricsfakes/fake_impl.go \
		--skip internal/pkg/nonrootenabler/nonrootenablerfakes/fake_impl.go \
		--skip internal/pkg/webhooks/binding/bindingfakes/fake_impl.go \
		--skip internal/pkg/webhooks/recording/recordingfakes/fake_impl.go \
		--skip internal/pkg/daemon/profilerecorder/profilerecorderfakes/fake_impl.go


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
	GL_DEBUG=gocritic $(BUILD_DIR)/golangci-lint run --build-tags $(LINT_BUILDTAGS)

$(BUILD_DIR)/golangci-lint:
	export \
		VERSION=$(GOLANGCI_LINT_VERSION) \
		URL=https://raw.githubusercontent.com/golangci/golangci-lint \
		BINDIR=$(BUILD_DIR) && \
	curl -sfL $$URL/$$VERSION/install.sh | sh -s $$VERSION
	$(BUILD_DIR)/golangci-lint version
	$(BUILD_DIR)/golangci-lint linters


.PHONY: verify-dependencies
verify-dependencies: $(BUILD_DIR)/zeitgeist ## Verify external dependencies
	$(BUILD_DIR)/zeitgeist validate --local-only --base-path . --config dependencies.yaml

$(BUILD_DIR)/zeitgeist: $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/zeitgeist \
		https://storage.googleapis.com/k8s-artifacts-sig-release/kubernetes-sigs/zeitgeist/$(ZEITGEIST_VERSION)/zeitgeist-$(ARCH)-$(OS)
	chmod +x $(BUILD_DIR)/zeitgeist

.PHONY: verify-toc
verify-toc: update-toc ## Verify the table of contents for the documentation
	hack/tree-status

.PHONY: verify-mocks
verify-mocks: update-mocks ## Verify the content of the generated mocks
	hack/tree-status

.PHONY: verify-bpf
verify-bpf: update-bpf ## Verify the generated bpf code
	hack/tree-status

.PHONY: verify-btf
verify-btf: update-btf ## Verify the generated btf code
	git diff

.PHONY: verify-format
verify-format: ## Verify the code format
	clang-format -i $(shell find . -type f -name '*.c' -or -name '*.proto' | grep -v ./vendor)
	hack/tree-status

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
	CGO_LDFLAGS= \
	E2E_SKIP_FLAKY_TESTS=true \
	$(GO) test -parallel 1 -timeout 60m -count=1 ./test -v

.PHONY: test-flaky-e2e
test-flaky-e2e: ## Only run the flaky end-to-end tests
	CGO_LDFLAGS= \
	E2E_SKIP_FLAKY_TESTS=false \
	$(GO) test -parallel 1 -timeout 20m -count=1 ./test -v -testify.m '^(TestSecurityProfilesOperator_Flaky)$$'

.PHONY: test-spoc-e2e
test-spoc-e2e: build/spoc
	$(GO) test -v ./test/spoc

# Generate CRD manifests
manifests: $(BUILD_DIR)/kubernetes-split-yaml $(BUILD_DIR)/kustomize
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/spod/...' output:crd:stdout" "deploy/base-crds/crds/securityprofilesoperatordaemon.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/secprofnodestatus/...' output:crd:stdout" "deploy/base-crds/crds/securityprofilenodestatus.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/seccompprofile/...' output:crd:stdout" "deploy/base-crds/crds/seccompprofile.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/selinuxprofile/...' output:crd:stdout" "deploy/base-crds/crds/selinuxpolicy.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/profilebinding/...' output:crd:stdout" "deploy/base-crds/crds/profilebinding.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/profilerecording/...' output:crd:stdout" "deploy/base-crds/crds/profilerecording.yaml"

# Generate deepcopy code
generate:
	$(CONTROLLER_GEN_CMD) object:headerFile="hack/boilerplate/boilerplate.go.txt",year=$(shell date -u "+%Y") paths="./api/..."
	$(CONTROLLER_GEN_CMD) rbac:roleName=security-profiles-operator paths="./internal/pkg/manager/..." output:rbac:stdout > deploy/base/role.yaml
	$(CONTROLLER_GEN_CMD) rbac:roleName=spod paths="./internal/pkg/daemon/..." output:rbac:stdout >> deploy/base/role.yaml
	$(CONTROLLER_GEN_CMD) rbac:roleName=spo-webhook paths="./internal/pkg/webhooks/..." output:rbac:stdout >> deploy/base/role.yaml

## Bundle packaging begins here
## read more at https://sdk.operatorframework.io/docs/olm-integration/tutorial-bundle/

.PHONY: operator-sdk
OPERATOR_SDK = $(BUILD_DIR)/operator-sdk
operator-sdk: $(BUILD_DIR) ## Download sdk locally if necessary.
ifeq (,$(wildcard $(OPERATOR_SDK)))
ifeq (,$(shell which operator-sdk 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPERATOR_SDK)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPERATOR_SDK) https://github.com/operator-framework/operator-sdk/releases/download/${OPERATOR_SDK_VERSION}/operator-sdk_$${OS}_$${ARCH} ;\
	chmod +x $(OPERATOR_SDK) ;\
	}
else
OPERATOR_SDK = $(shell which operator-sdk)
endif
endif


# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
CHANNELS="stable"
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
DEFAULT_CHANNEL="stable"
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(PROJECT)-bundle:v$(VERSION)

# The operator manifest to include in the CSV. Defaults to the cluster-scoped
# operator. Can be only one
BUNDLE_OPERATOR_MANIFEST ?= deploy/operator.yaml

# These examples are added to the alm-examples annotation and subsequently
# displayed in the UI. Keep the separator last.
OLM_EXAMPLES := \
	examples/apparmorprofile.yaml \
	examples/config.yaml \
	examples/profilerecording-seccomp-bpf.yaml \
	examples/profilebinding.yaml \
	examples/rawselinuxprofile.yaml \
	examples/seccompprofile.yaml \
	examples/selinuxprofile.yaml \
	deploy/separator.yaml

BUNDLE_SA_OPTS ?= --extra-service-accounts security-profiles-operator,spod,spo-webhook

.PHONY: bundle
bundle: operator-sdk deployments ## Generate bundle manifests and metadata, then validate generated files.
	$(SED) "s/\(olm.skipRange: '>=.*\)<.*'/\1<$(VERSION)'/" deploy/base/clusterserviceversion.yaml
	$(SED) "s/\(\"name\": \"security-profiles-operator.v\).*\"/\1$(VERSION)\"/" deploy/catalog-preamble.json
	$(SED) "s/\(\"skipRange\": \">=.*\)<.*\"/\1<$(VERSION)\"/" deploy/catalog-preamble.json
	cat $(OLM_EXAMPLES) $(BUNDLE_OPERATOR_MANIFEST) deploy/base/clusterserviceversion.yaml | $(OPERATOR_SDK) generate bundle -q --overwrite $(BUNDLE_SA_OPTS) --version $(VERSION) $(BUNDLE_METADATA_OPTS)
	git restore deploy/base/clusterserviceversion.yaml
	mkdir -p ./bundle/tests/scorecard
	cp deploy/bundle-test-config.yaml ./bundle/tests/scorecard/config.yaml
	$(OPERATOR_SDK) bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	$(CONTAINER_RUNTIME) build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(CONTAINER_RUNTIME) push $(BUNDLE_IMG)

.PHONY: verify-bundle
verify-bundle: bundle ## Verify the bundle doesn't alter the state of the tree
	git diff -I'^    createdAt: '

.PHONY: opm
OPM = $(BUILD_DIR)/opm
opm: $(BUILD_DIR) ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/$(OPERATOR_SDK_VERSION)/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(PROJECT)-catalog:v$(VERSION)

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This target uses the file-based catalog format (https://olm.operatorframework.io/docs/reference/file-based-catalogs/)
.PHONY: catalog-build
catalog-build: opm ## Build a catalog image.
	$(eval TMP_DIR := $(shell mktemp -d))
	$(eval CATALOG_DOCKERFILE := $(TMP_DIR).Dockerfile)
	cp deploy/catalog-preamble.json $(TMP_DIR)/security-profiles-operator-catalog.json
	$(OPM) $(OPM_EXTRA_ARGS) render $(BUNDLE_IMGS) >> $(TMP_DIR)/security-profiles-operator-catalog.json
	$(OPM) generate dockerfile $(TMP_DIR)
	$(CONTAINER_RUNTIME) build -f $(CATALOG_DOCKERFILE) -t $(CATALOG_IMG) $(shell dirname $(TMP_DIR))
	rm -rf $(TMP_DIR) $(CATALOG_DOCKERFILE)

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(CONTAINER_RUNTIME) push $(CATALOG_IMG)

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
	@echo "Deploying"
	oc apply -f deploy/openshift-dev.yaml
	@echo "Setting triggers to track image"
	oc set triggers -n security-profiles-operator deployment/security-profiles-operator --from-image openshift/security-profiles-operator:latest -c security-profiles-operator

# Deploy for development into OpenShift
.PHONY: deploy-openshift-dev
deploy-openshift-dev: push-openshift-dev do-deploy-openshift-dev


# Deploy the operator into the current kubectl context.
.PHONY: deploy
deploy:
	mkdir -p build/deploy && cp deploy/operator.yaml build/deploy/
	$(SED) "s#gcr.io/k8s-staging-sp-operator/security-profiles-operator:latest#$(IMAGE)#g" build/deploy/operator.yaml
	$(SED) "s#replicas: 3#replicas: 1#g" build/deploy/operator.yaml
	kubectl apply -f build/deploy/operator.yaml
	kubectl apply -f examples/config.yaml
