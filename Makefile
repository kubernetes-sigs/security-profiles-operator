# Copyright The Kubernetes Authors.
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

GOLANGCI_LINT_VERSION = v2.14.0
# Checksums of the golangci-lint release archives per GOOS_GOARCH, see
# golangci-lint-<version>-checksums.txt of the release. Bump them together
# with the version above.
GOLANGCI_LINT_SHA256_linux_amd64 = ab90aeb7b066f92a33415b638a50fe5344bbb75a0d32ad30cc248d88f81032ab
GOLANGCI_LINT_SHA256_linux_arm64 = ee7ec5f3453d15ddf106fae5a4d6c71737712348a979d1fe9cd52ec7ea299bae
GOLANGCI_LINT_SHA256_darwin_amd64 = a5667c1c3536be1740133213e1e822bfb8f0d98ea12903174d6d5f635e4ed68d
GOLANGCI_LINT_SHA256_darwin_arm64 = 5ef5f36a7147e91dc58ef9ef4d11bb7bad5ead0c76eb6c01327a73c641d1dcc3
KAL_VERSION = v0.0.0-20260716143926-092fe0c72997
REPO_INFRA_VERSION = v0.2.6
# Checksum of hack/verify_boilerplate.py of REPO_INFRA_VERSION.
VERIFY_BOILERPLATE_SHA256 = 3ee0139a0a2865ad2e9674012a2459d56f4009844aa1b430119d0da4c603da95
KUSTOMIZE_VERSION = 5.8.1
OPERATOR_SDK_VERSION ?= v1.42.3
OPM_VERSION ?= v1.74.0
# Checksums of the operator-sdk and opm release binaries per GOOS_GOARCH, bump
# them together with the versions above.
OPERATOR_SDK_SHA256_linux_amd64 = 887a3bb0d63ccc4ca47a522d0c8ffac56d9d5246f6a2bd886b4ed23eb2e2672f
OPERATOR_SDK_SHA256_linux_arm64 = 6db93cd821b429f0bb514cea4bbb5553827d273fc8aa211f13e14798599d31cd
OPERATOR_SDK_SHA256_darwin_amd64 = 7cb0f24bb63b6383a117291ee4c808953c5dd789d5877da98051aa68b41f40ac
OPERATOR_SDK_SHA256_darwin_arm64 = 098ae8b9dbe7dfd557e8e7ed0f1996736922dd4b984621df2aa033f225cae161
OPM_SHA256_linux_amd64 = cf1bd699be72e0a4511208afdf45444fc47d21eb2ffed0c204520ff50b5a4691
OPM_SHA256_linux_arm64 = 348a9682975eb220bea3b98b83aa82dc6d2630e6868331ed9bf14f97e462d8be
OPM_SHA256_darwin_amd64 = a448e5972689036cb1168b83e18195b193bb513399c234d402c425b073a52ea6
OPM_SHA256_darwin_arm64 = 0ce2671c543e637ae24cb98dfeeec1a9554e3955a72c59eb872750eaf915627f
ZEITGEIST_VERSION = v0.8.0
MDTOC_VERSION = v1.4.0
GOVULNCHECK_VERSION = v1.8.0
GOTESTSUM_VERSION = v1.13.0
# setup-envtest downloads the kube-apiserver and etcd binaries of the
# integration tests. It is released together with controller-runtime, bump
# them together.
SETUP_ENVTEST_VERSION = v0.25.2
SHELLCHECK_VERSION = v0.11.0
# Checksums of the shellcheck release archives per GOOS_GOARCH, bump them
# together with the version above.
SHELLCHECK_SHA256_linux_amd64 = 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
SHELLCHECK_SHA256_linux_arm64 = 12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
SHELLCHECK_SHA256_darwin_amd64 = 3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6
SHELLCHECK_SHA256_darwin_arm64 = 56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79
PROTOC_VERSION = v36.2
# Checksums of the protoc release archives per GOOS_GOARCH, bump them together
# with the version above. The version ends up in the headers of the generated
# GRPC code.
PROTOC_SHA256_linux_amd64 = 121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278
PROTOC_SHA256_linux_arm64 = 8b8f18bd2b30346efbc698dd5a73dd7c805f3ef8380f6dfc95c768f3f1852f6a
PROTOC_SHA256_darwin_amd64 = 228cc7add4616cc14ca5e80dee83209d44449a7aee95a914ae748fa374efb078
PROTOC_SHA256_darwin_arm64 = 9cd98a532c5c5e0c4161314de0225de27e4c8a323917b6ea7b1b714d3ae23466
HADOLINT_VERSION = v2.15.1
# Checksums of the hadolint release binaries per GOOS_GOARCH, see
# checksums.sha256 of the release. Bump them together with the version above.
HADOLINT_SHA256_linux_amd64 = c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507
HADOLINT_SHA256_linux_arm64 = f6198ef8090f404dbb771abfee086eb8c48ac177f30da7fd3510aca35b344b5d
HADOLINT_SHA256_darwin_amd64 = ffe9bb18b23d5ed1eae50237aecdbb523d016e96da0bd4e7aa432040acfc3fde
HADOLINT_SHA256_darwin_arm64 = 5c09f3213f8e40406abe048233d985eebef336d4a6a20021be47fadb6cf480a2
ACTIONLINT_VERSION = v1.7.12
KUBECONFORM_VERSION = v0.8.0
KUBE_LINTER_VERSION = v0.8.3
YQ_VERSION = 4.53.6
# The oldest Kubernetes release the manifests are validated against, see
# minimum-kubernetes in dependencies.yaml.
MIN_KUBERNETES_VERSION = 1.30.0
# Go tools which run outside of the module, so they need no vendoring. The
# module checksum database verifies them.
GO_RUN_TOOL := GOFLAGS= CGO_ENABLED=0 $(GO) run
# Runs outside of the module, so it needs no vendoring.
GOTESTSUM := GOFLAGS= $(GO) run gotest.tools/gotestsum@$(GOTESTSUM_VERSION)
CI_IMAGE ?= golang:$(shell hack/go-version.sh)

CONTROLLER_GEN_CMD := CGO_LDFLAGS= $(GO) run $(BUILD_FLAGS) -tags generate sigs.k8s.io/controller-tools/cmd/controller-gen

NIX := nix --extra-experimental-features 'nix-command flakes'

# The GOOS_GOARCH of the downloaded tools, which selects their checksum.
TOOLS_PLATFORM = $(shell $(GO) env GOOS)_$(shell $(GO) env GOARCH)
SHA256SUM ?= $(shell command -v sha256sum 2>/dev/null || echo shasum -a 256)

PROJECT := security-profiles-operator
CLI_BINARY := spoc
BUILD_DIR := build

APPARMOR_ENABLED ?= 1
BPF_ENABLED ?= 1

# Booting a test VM takes under 7 minutes, so anything beyond this is a hang
# rather than a slow host. GNU coreutils' timeout is called gtimeout on macOS,
# and where neither exists the boot just stays unbounded as it was before.
VAGRANT_UP_TIMEOUT ?= 20m
TIMEOUT_CMD := $(shell command -v timeout || command -v gtimeout)
ifneq ($(TIMEOUT_CMD),)
VAGRANT_UP_LIMIT := $(TIMEOUT_CMD) -k 1m $(VAGRANT_UP_TIMEOUT)
VAGRANT_DESTROY_LIMIT := $(TIMEOUT_CMD) -k 30s 5m
endif

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH ?= $(shell uname -m | \
	sed 's/x86_64/amd64/' | \
	sed 's/aarch64/arm64/' | \
	sed 's/ppc64le/powerpc/' | \
	sed 's/mips.*/mips/')

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
LINT_BUILDTAGS := e2e,integration,netgo,osusergo,seccomp
else
LINT_BUILDTAGS := e2e,integration,netgo,osusergo
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

# vendor/modules.txt changes with every dependency change, walking all of
# vendor on every make invocation is not worth it.
BUILD_FILES := $(shell find . \( -path ./vendor -o -path ./.git -o -path ./$(BUILD_DIR) \) -prune -o -type f \( -name '*.go' -or -name '*.mod' -or -name '*.sum' -or -name 'recorder.bpf.o.*' \) -not -name '*_test.go' -print) vendor/modules.txt
BPF_RECORDER_PATH := internal/pkg/daemon/bpfrecorder/bpf
BPF_RECORDER_FILES := $(shell find internal/pkg/daemon/bpfrecorder/bpf -type f \( -name '*.c' -or -name '*.h' \))
BPF_RECORDER_OUTPUT_FILES := $(shell find internal/pkg/daemon/bpfrecorder/bpf -type f -name 'recorder.bpf.o.*')
BPF_ENRICHER_PATH := internal/pkg/daemon/enricher/auditsource/bpf
BPF_ENRICHER_FILES := $(shell find internal/pkg/daemon/enricher/auditsource/bpf -type f \( -name '*.c' -or -name '*.h' \))
BPF_ENRICHER_OUTPUT_FILES := $(shell find internal/pkg/daemon/enricher/auditsource/bpf -type f -name 'enricher.bpf.o.*')
BPF_OUTPUT_FILES := $(BPF_RECORDER_OUTPUT_FILES) $(BPF_ENRICHER_OUTPUT_FILES)
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

# -w drops DWARF, but the symbol table has to stay: govulncheck reads it to
# tell which packages of a vulnerable module the binary actually uses. With
# -s it falls back to module level and reports every vulnerability of every
# module in the build info as affected, which makes the attested VEX
# documents claim vulnerabilities the binaries don't contain.
LINKMODE_EXTERNAL ?= yes
ifeq ($(LINKMODE_EXTERNAL), yes)
  LDFLAGS := -w -linkmode external $(EXTLDFLAGS) $(LDVARS)
else
  LDFLAGS := -w $(EXTLDFLAGS) $(LDVARS)
endif

export CONTAINER_RUNTIME ?= $(if $(shell which podman 2>/dev/null),podman,docker)

# The route of the OpenShift image registry of a development cluster may have
# a self-signed certificate. REGISTRY_TLS_VERIFY=false makes podman skip the
# verification for the login and the push, docker takes insecure registries
# from its daemon configuration instead.
REGISTRY_TLS_VERIFY ?= true
ifeq ($(CONTAINER_RUNTIME)-$(REGISTRY_TLS_VERIFY), podman-false)
    LOGIN_PUSH_OPTS = --tls-verify=false
else
    LOGIN_PUSH_OPTS =
endif

IMAGE ?= $(PROJECT):latest

CRD_OPTIONS ?= "crd:crdVersions=v1"

export E2E_CLUSTER_TYPE ?= kind

DOCKERFILE ?= Dockerfile

COLOR := \033[36m
NOCOLOR := \033[0m

# Utility targets

.PHONY: all manifests generate
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

# The build directory is an order-only prerequisite, its timestamp changes
# with every file written to it and must not trigger a rebuild.
$(BUILD_DIR)/$(PROJECT): $(BUILD_FILES) | $(BUILD_DIR)
	$(call go-build-spo,$(PROJECT))

$(BUILD_DIR)/$(CLI_BINARY): $(BUILD_FILES) | $(BUILD_DIR)
	$(call go-build-spo,$(CLI_BINARY))

.PHONY: clean
clean: ## Clean the build directory
	rm -rf $(BUILD_DIR) $(BPF_OUTPUT_FILES)

# kustomize shapes the committed manifests and the OLM bundle. It is built
# from source, the module checksum database verifies it. The binary is
# versioned, so that a bump of KUSTOMIZE_VERSION installs the new one.
KUSTOMIZE := $(BUILD_DIR)/kustomize-v$(KUSTOMIZE_VERSION)

$(KUSTOMIZE): | $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR))/kustomize-install GOFLAGS= CGO_ENABLED=0 \
		$(GO) install sigs.k8s.io/kustomize/kustomize/v5@v$(KUSTOMIZE_VERSION)
	mv $(BUILD_DIR)/kustomize-install/kustomize $@
	rm -rf $(BUILD_DIR)/kustomize-install

$(BUILD_DIR)/kustomize: $(KUSTOMIZE)
	ln -sf $(notdir $(KUSTOMIZE)) $@

$(BUILD_DIR)/kubernetes-split-yaml: | $(BUILD_DIR)
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

# The OCI image annotations and the build date of Dockerfile.ubi come from the
# commit, so that a commit gives the same image metadata.
IMAGE_REVISION = $(shell git rev-parse HEAD 2>/dev/null)
IMAGE_SOURCE_DATE_EPOCH = $(shell git log -1 --format=%ct 2>/dev/null)
# The commit time like hack/image-cross.sh, BUILD_DATE outside of a git tree.
IMAGE_CREATED = $(or $(if $(IMAGE_SOURCE_DATE_EPOCH),$(shell date -u -d "@$(IMAGE_SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(IMAGE_SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null)),$(BUILD_DATE))
IMAGE_BUILD_ARGS = \
	--build-arg version=$(VERSION) \
	--build-arg revision=$(IMAGE_REVISION) \
	--build-arg created=$(IMAGE_CREATED) \
	--build-arg SOURCE_DATE_EPOCH=$(IMAGE_SOURCE_DATE_EPOCH)

.PHONY: image
image: ## Build the container image
	$(CONTAINER_RUNTIME) build -f $(DOCKERFILE) $(IMAGE_BUILD_ARGS) -t $(IMAGE) .

.PHONY: image-arm64
image-arm64: ## Build the container image for arm64
	$(CONTAINER_RUNTIME) build -f $(DOCKERFILE) \
		--platform linux/arm64 \
		$(IMAGE_BUILD_ARGS) \
		--build-arg target=spo-arm64 \
		-t $(IMAGE) .

.PHONY: image-cross
image-cross: ## Build and push the container image manifest
	hack/image-cross.sh

# Every nix build gets its own result link, so that the targets can run in
# parallel with make -j.
define nix-build-to
	$(NIX) build --out-link result-spo-$(1) .#spo-$(1)
	mkdir -p $(BUILD_DIR)/$(1)
	cp -f result-spo-$(1)/* $(BUILD_DIR)/$(1)
endef

# TODO: add nix-s390x when the nix musl toolchain is fixed. spoc is not affected
# because nix-spoc-s390x builds against glibc.
.PHONY: nix
nix: nix-amd64 nix-arm64 nix-ppc64le  ## Build all binaries via nix and create a build.tar.gz
	tar cvfz build.tar.gz -C $(BUILD_DIR) amd64 arm64 ppc64le

.PHONY: nix-amd64
nix-amd64: ## Build the binaries via nix for amd64
	$(call nix-build-to,amd64)

.PHONY: nix-arm64
nix-arm64: ## Build the binaries via nix for arm64
	$(call nix-build-to,arm64)

.PHONY: nix-ppc64le
nix-ppc64le: ## Build the binaries via nix for ppc64le
	$(call nix-build-to,ppc64le)

.PHONY: nix-s390x
nix-s390x: ## Build the binaries via nix for s390x
	$(call nix-build-to,s390x)

SPOC_ARCHES := amd64 arm64 ppc64le s390x

# The released binaries are always built from source. Only their dependencies
# (the inputDerivation closure) may come from the binary caches, so that a
# poisoned cache entry cannot stand in for them.
define nix-build-spoc-to
	$(NIX) build --no-link .#spoc-$(1).inputDerivation
	$(NIX) build --option substitute false --out-link result-spoc-$(1) .#spoc-$(1)
	cp -f result-spoc-$(1)/spoc $(BUILD_DIR)/spoc.$(1)
	cd $(BUILD_DIR) && sha512sum spoc.$(1) > spoc.$(1).sha512
endef

.PHONY: nix-spoc
nix-spoc: nix-spoc-amd64 nix-spoc-arm64 nix-spoc-ppc64le nix-spoc-s390x ## Build all spoc binaries via nix.
	$(MAKE) spoc-sbom spoc-sign

# The build workflow signs in a separate job, so that the build steps never
# hold the signing identity.
.PHONY: spoc-sign
spoc-sign: ## Sign the spoc binaries and their SBOMs in the build directory
	$(foreach file,$(SPOC_ARCHES:%=spoc.%) spoc.spdx.json spoc-native.spdx.json,cosign sign-blob -y $(BUILD_DIR)/$(file) --bundle $(BUILD_DIR)/$(file).sigstore.json &&) true

# bom lists the Go modules from the build information embedded in the
# binaries, so the SBOM has the versions that were actually built in, apart
# from the one of this module, see hack/set-sbom-module-version.sh. The C
# libraries the binaries link statically come from the nix build inputs.
.PHONY: spoc-sbom
spoc-sbom: ## Generate the SBOMs for the spoc binaries in the build directory
	bom version
	bom generate \
		--format spdx3-json \
		--name spoc \
		$(foreach arch,$(SPOC_ARCHES),-f $(BUILD_DIR)/spoc.$(arch)) \
		-o $(BUILD_DIR)/spoc.spdx.json
	hack/set-sbom-module-version.sh $(BUILD_DIR)/spoc.spdx.json
	hack/native-sbom.sh spoc-native $(BUILD_DIR)/spoc-native.spdx.json $(SPOC_ARCHES:%=spoc-%)

.PHONY: nix-spoc-amd64
nix-spoc-amd64: $(BUILD_DIR) ## Build the spoc binary via nix for amd64
	$(call nix-build-spoc-to,amd64)

.PHONY: nix-spoc-arm64
nix-spoc-arm64: $(BUILD_DIR) ## Build the spoc binary via nix for arm64
	$(call nix-build-spoc-to,arm64)

.PHONY: nix-spoc-ppc64le
nix-spoc-ppc64le: $(BUILD_DIR) ## Build the spoc binary via nix for ppc64le
	$(call nix-build-spoc-to,ppc64le)

.PHONY: nix-spoc-s390x
nix-spoc-s390x: $(BUILD_DIR) ## Build the spoc binary via nix for s390x
	$(call nix-build-spoc-to,s390x)

.PHONY: update-nixpkgs
update-nixpkgs: ## Update the pinned nixpkgs to the latest master
	$(NIX) flake update

.PHONY: update-go-mod
update-go-mod: ## Cleanup, vendor and verify go modules
	$(GO) mod tidy && \
		$(GO) mod vendor && \
		$(GO) mod verify

.PHONY: push-base-profiles
push-base-profiles: $(BUILD_DIR)/$(CLI_BINARY) ## Publish the recorded base profiles as OCI artifacts
	./hack/push-base-profiles.sh

.PHONY: push-test-artifacts
push-test-artifacts: $(BUILD_DIR)/$(CLI_BINARY) ## Push the KEP-6061 e2e test artifacts to the staging registry
	./hack/push-test-artifacts.sh

.PHONY: update-mocks
update-mocks: ## Update all generated mocks
	$(GO) generate ./...

define go-build
	CGO_LDFLAGS= $(GO) build -o $(BUILD_DIR)/$(shell basename $(1)) $(1)
endef

$(BUILD_DIR)/protoc-gen-go-grpc: | $(BUILD_DIR)
	$(call go-build,./vendor/google.golang.org/grpc/cmd/protoc-gen-go-grpc)

$(BUILD_DIR)/protoc-gen-go: | $(BUILD_DIR)
	$(call go-build,./vendor/google.golang.org/protobuf/cmd/protoc-gen-go)

PROTOC := $(BUILD_DIR)/protoc-$(PROTOC_VERSION)
# protoc names the release archives by osx and aarch_64.
PROTOC_ARCHIVE = protoc-$(PROTOC_VERSION:v%=%)-$(subst darwin,osx,$(shell $(GO) env GOOS))-$(subst arm64,aarch_64,$(subst amd64,x86_64,$(shell $(GO) env GOARCH))).zip

$(PROTOC): | $(BUILD_DIR)
	rm -rf $@.install
	mkdir -p $@.install
	curl -sSfL --retry 5 --retry-delay 3 -o $@.install/archive.zip \
		https://github.com/protocolbuffers/protobuf/releases/download/$(PROTOC_VERSION)/$(PROTOC_ARCHIVE)
	echo "$(PROTOC_SHA256_$(TOOLS_PLATFORM))  $@.install/archive.zip" | $(SHA256SUM) -c -
	unzip -q $@.install/archive.zip bin/protoc -d $@.install
	mv $@.install/bin/protoc $@
	rm -rf $@.install
	$@ --version

.PHONY: update-proto
update-proto: $(PROTOC) $(BUILD_DIR)/protoc-gen-go $(BUILD_DIR)/protoc-gen-go-grpc ## Update GRPC server protocol definitions
	for PROTO in \
		api/grpc/metrics \
		api/grpc/enricher \
		api/grpc/bpfrecorder \
	; do \
	PATH=$(BUILD_DIR):$$PATH \
		 $(PROTOC) \
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
	# A half provisioned VM cannot be resumed by another `vagrant up`, so retry
	# from a clean one in case a temporarily unavailable remote resource (like
	# the VM image or a package mirror) broke the boot. The timeouts are what
	# make that retry reachable: VirtualBox does hang while starting a VM, and
	# a `vagrant up` that never returns just burns the whole CI job.
	$(VAGRANT_UP_LIMIT) vagrant up || { \
		$(VAGRANT_DESTROY_LIMIT) vagrant destroy -f || true; \
		$(VAGRANT_UP_LIMIT) vagrant up; \
	}
endef

.PHONY: vagrant-up-fedora
vagrant-up-fedora: ## Boot the Vagrant Fedora based test VM
	$(call vagrant-up,fedora,build)

.PHONY: vagrant-up-debian
vagrant-up-debian: ## Boot the Vagrant Debian based test VM
	$(call vagrant-up,debian,build)

.PHONY: vagrant-up-flatcar
vagrant-up-flatcar: ## Boot the Vagrant Flatcar based test VM
	$(call vagrant-up,flatcar,build)

# Built from source, the module checksum database verifies it.
$(BUILD_DIR)/mdtoc: | $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) GOFLAGS= CGO_ENABLED=0 $(GO) install sigs.k8s.io/mdtoc@$(MDTOC_VERSION)

.PHONY: update-toc
update-toc: $(BUILD_DIR)/mdtoc ## Update the table of contents for the documentation
	git grep --name-only '<!-- toc -->' | grep -v Makefile | xargs $(BUILD_DIR)/mdtoc -i

.PHONY: update-docs
update-docs: ## Update the generated command line reference in doc/reference
	$(GO) run ./cmd/spoc docs > doc/reference/spoc.md
	$(GO) run ./cmd/security-profiles-operator docs > doc/reference/security-profiles-operator.md

# Called by nix/derivation-bpf.nix with ARCH set to the kernel architecture
# name of the vmlinux directory, use make update-bpf to build them.
$(BUILD_DIR)/recorder.bpf.o: $(BPF_RECORDER_FILES) | $(BUILD_DIR)
	$(CLANG) -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		$(CFLAGS) \
		-I ./internal/pkg/daemon/bpfrecorder/vmlinux/$(ARCH) \
		-c $(BPF_RECORDER_PATH)/recorder.bpf.c \
		-o $@
	$(LLVM_STRIP) -g $@

$(BUILD_DIR)/enricher.bpf.o: $(BPF_ENRICHER_FILES) | $(BUILD_DIR)
	$(CLANG) -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		$(CFLAGS) \
		-I ./internal/pkg/daemon/bpfrecorder/vmlinux/$(ARCH) \
		-c $(BPF_ENRICHER_PATH)/enricher.bpf.c \
		-o $@
	$(LLVM_STRIP) -g $@

.PHONY: update-vmlinux
update-vmlinux: ## Generate the vmlinux.h required for building the BPF modules.
	./hack/update-vmlinux

BPF_UPDATE_OBJECTS := \
    internal/pkg/daemon/bpfrecorder/bpf/recorder.bpf.o.amd64 \
    internal/pkg/daemon/bpfrecorder/bpf/recorder.bpf.o.arm64 \
    internal/pkg/daemon/enricher/auditsource/bpf/enricher.bpf.o.amd64 \
    internal/pkg/daemon/enricher/auditsource/bpf/enricher.bpf.o.arm64

.PHONY: update-bpf
update-bpf: clean $(BPF_UPDATE_OBJECTS) ## Build and update all generated BPF code with nix

# The objects of an architecture, use make update-bpf to build all of them.
internal/pkg/daemon/bpfrecorder/bpf/recorder.bpf.o.%: $(BPF_RECORDER_FILES)
	$(NIX) build --out-link result-bpf-recorder-$* .#bpf-$*
	cp -f result-bpf-recorder-$*/recorder.bpf.o ./internal/pkg/daemon/bpfrecorder/bpf/recorder.bpf.o.$*
	chmod 0644 ./internal/pkg/daemon/bpfrecorder/bpf/recorder.bpf.o.$*

internal/pkg/daemon/enricher/auditsource/bpf/enricher.bpf.o.%: $(BPF_ENRICHER_FILES)
	$(NIX) build --out-link result-bpf-enricher-$* .#bpf-$*
	cp -f result-bpf-enricher-$*/enricher.bpf.o ./internal/pkg/daemon/enricher/auditsource/bpf/enricher.bpf.o.$*
	chmod 0644 ./internal/pkg/daemon/enricher/auditsource/bpf/enricher.bpf.o.$*

# Verification targets

.PHONY: verify
verify: verify-boilerplate verify-go-mod verify-go-lint verify-deployments verify-dependencies verify-toc verify-mocks verify-proto verify-format verify-vulnerabilities verify-shellcheck verify-dockerfiles verify-manifests verify-security-model verify-docs ## Run all verification targets

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
# The skipped files are generated, by substring of their path.
verify-boilerplate: $(BUILD_DIR)/verify_boilerplate.py ## Verify the boilerplate headers for all files
	$(BUILD_DIR)/verify_boilerplate.py \
		--boilerplate-dir hack/boilerplate \
		--skip api/grpc/ \
		--skip zz_generated.deepcopy.go \
		--skip fakes/fake_


$(BUILD_DIR)/verify_boilerplate.py: | $(BUILD_DIR)
	curl -sSfL --retry 5 --retry-delay 3 -o $@.download \
		https://raw.githubusercontent.com/kubernetes/repo-infra/$(REPO_INFRA_VERSION)/hack/verify_boilerplate.py
	echo "$(VERIFY_BOILERPLATE_SHA256)  $@.download" | $(SHA256SUM) -c -
	chmod +x $@.download
	mv $@.download $@

.PHONY: verify-go-mod
verify-go-mod: update-go-mod ## Verify the go modules
	hack/tree-status

.PHONY: verify-deployments
verify-deployments: deployments ## Verify the generated deployments
	hack/tree-status

.PHONY: verify-go-lint
verify-go-lint: $(BUILD_DIR)/golangci-lint-kube-api-linter ## Verify the golang code by linting
	$(BUILD_DIR)/golangci-lint-kube-api-linter run --build-tags $(LINT_BUILDTAGS)

# The binaries are versioned, so that a bump of GOLANGCI_LINT_VERSION or
# .custom-gcl.yml rebuilds them instead of linting with a stale binary.
GOLANGCI_LINT := $(BUILD_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)

GOLANGCI_LINT_ARCHIVE = golangci-lint-$(GOLANGCI_LINT_VERSION:v%=%)-$(subst _,-,$(TOOLS_PLATFORM))

$(GOLANGCI_LINT): | $(BUILD_DIR)
	rm -rf $(BUILD_DIR)/golangci-lint-install
	mkdir -p $(BUILD_DIR)/golangci-lint-install
	curl -sSfL --retry 5 --retry-delay 3 -o $(BUILD_DIR)/golangci-lint-install/archive.tar.gz \
		https://github.com/golangci/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION)/$(GOLANGCI_LINT_ARCHIVE).tar.gz
	echo "$(GOLANGCI_LINT_SHA256_$(TOOLS_PLATFORM))  $(BUILD_DIR)/golangci-lint-install/archive.tar.gz" | $(SHA256SUM) -c -
	tar -xzf $(BUILD_DIR)/golangci-lint-install/archive.tar.gz -C $(BUILD_DIR)/golangci-lint-install \
		--strip-components=1 $(GOLANGCI_LINT_ARCHIVE)/golangci-lint
	mv $(BUILD_DIR)/golangci-lint-install/golangci-lint $@
	rm -rf $(BUILD_DIR)/golangci-lint-install
	$@ version

$(BUILD_DIR)/golangci-lint-kube-api-linter: $(GOLANGCI_LINT) .custom-gcl.yml
	CGO_ENABLED=0 GOFLAGS=-mod=mod $(GOLANGCI_LINT) custom
	$@ version
	$@ linters


.PHONY: verify-vulnerabilities
verify-vulnerabilities: ## Verify that no known vulnerability is reachable
	GOVULNCHECK_VERSION=$(GOVULNCHECK_VERSION) BUILDTAGS='$(BUILDTAGS)' hack/govulncheck

.PHONY: verify-dependencies
verify-dependencies: $(BUILD_DIR)/zeitgeist ## Verify external dependencies
	$(BUILD_DIR)/zeitgeist validate --local-only --base-path . --config dependencies.yaml

# Built from source, the module checksum database verifies it.
$(BUILD_DIR)/zeitgeist: | $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) GOFLAGS= CGO_ENABLED=0 $(GO) install sigs.k8s.io/zeitgeist@$(ZEITGEIST_VERSION)

.PHONY: verify-toc
verify-toc: update-toc ## Verify the table of contents for the documentation
	hack/tree-status

.PHONY: verify-docs
verify-docs: update-docs ## Verify the generated command line reference
	hack/tree-status

.PHONY: verify-mocks
verify-mocks: update-mocks ## Verify the content of the generated mocks
	hack/tree-status

.PHONY: verify-proto
verify-proto: update-proto ## Verify the generated GRPC protocol definitions
	hack/tree-status

.PHONY: verify-bpf
verify-bpf: update-bpf ## Verify the generated bpf code
	hack/tree-status

# go.mod, the Dockerfiles and the workflows derive the Go version from go.mod
# and dependencies.yaml tracks the pinned copies, but nix brings its own Go
# with the nixpkgs revision in flake.lock.
.PHONY: verify-go-version
verify-go-version: ## Verify that nix builds with the Go version of go.mod
	@nix_go="$$($(NIX) eval --raw .#default.go.version)" && \
	go_mod="$$(hack/go-version.sh)" && \
	if [ "$$nix_go" != "$$go_mod" ]; then \
		echo "nix builds with Go $$nix_go, but go.mod wants $$go_mod" >&2; \
		exit 1; \
	fi

.PHONY: verify-format
verify-format: ## Verify the code format
	clang-format -i $(shell find . -type f -name '*.c' -or -name '*.proto' | grep -v ./vendor)
	hack/tree-status

# Architecture names of the shellcheck and hadolint release assets. shellcheck
# names arm64 aarch64, hadolint keeps arm64.
TOOLS_ASSET_ARCH = $(subst arm64,aarch64,$(subst amd64,x86_64,$(shell $(GO) env GOARCH)))
HADOLINT_ARCH = $(subst amd64,x86_64,$(shell $(GO) env GOARCH))
HADOLINT_OS = $(subst darwin,macos,$(shell $(GO) env GOOS))

SHELLCHECK := $(BUILD_DIR)/shellcheck-$(SHELLCHECK_VERSION)
SHELLCHECK_ARCHIVE = shellcheck-$(SHELLCHECK_VERSION).$(shell $(GO) env GOOS).$(TOOLS_ASSET_ARCH).tar.xz

$(SHELLCHECK): | $(BUILD_DIR)
	rm -rf $@.install
	mkdir -p $@.install
	curl -sSfL --retry 5 --retry-delay 3 -o $@.install/archive.tar.xz \
		https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/$(SHELLCHECK_ARCHIVE)
	echo "$(SHELLCHECK_SHA256_$(TOOLS_PLATFORM))  $@.install/archive.tar.xz" | $(SHA256SUM) -c -
	tar -xJf $@.install/archive.tar.xz -C $@.install --strip-components=1 shellcheck-$(SHELLCHECK_VERSION)/shellcheck
	mv $@.install/shellcheck $@
	rm -rf $@.install

.PHONY: verify-shellcheck
verify-shellcheck: $(SHELLCHECK) ## Verify the shell scripts with shellcheck
	SHELLCHECK=$(SHELLCHECK) hack/verify-shellcheck.sh

HADOLINT := $(BUILD_DIR)/hadolint-$(HADOLINT_VERSION)

$(HADOLINT): | $(BUILD_DIR)
	curl -sSfL --retry 5 --retry-delay 3 -o $@.download \
		https://github.com/hadolint/hadolint/releases/download/$(HADOLINT_VERSION)/hadolint-$(HADOLINT_OS)-$(HADOLINT_ARCH)
	echo "$(HADOLINT_SHA256_$(TOOLS_PLATFORM))  $@.download" | $(SHA256SUM) -c -
	chmod +x $@.download
	mv $@.download $@

.PHONY: verify-dockerfiles
verify-dockerfiles: $(HADOLINT) ## Lint the Dockerfiles and verify that the image variants match
	$(HADOLINT) --config .hadolint.yaml Dockerfile Dockerfile.ubi Dockerfile.build-image bundle.Dockerfile
	hack/ci/dockerfile-drift.sh Dockerfile Dockerfile.ubi

.PHONY: verify-actions
verify-actions: $(SHELLCHECK) ## Lint the GitHub workflows with actionlint
	$(GO_RUN_TOOL) github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) -shellcheck=$(abspath $(SHELLCHECK))

# The committed manifests and the examples are validated against the schemas
# of the oldest supported Kubernetes and of the CRDs in this tree, and the
# deployments are linted with kube-linter, see .kube-linter.yaml.
.PHONY: verify-manifests
verify-manifests: ## Validate the committed manifests and examples
	GO="$(GO)" \
	KUBECONFORM_VERSION=$(KUBECONFORM_VERSION) \
	KUBE_LINTER_VERSION=$(KUBE_LINTER_VERSION) \
	YQ_VERSION=$(YQ_VERSION) \
	KUBERNETES_VERSION=$(MIN_KUBERNETES_VERSION) \
	BUILD_DIR=$(BUILD_DIR) \
		hack/verify-manifests.sh

.PHONY: verify-security-model
verify-security-model: ## Verify that doc/security-model.md matches the manifests and the code
	hack/verify-security-model.sh

# Test targets

.PHONY: test-unit
# -coverpkg attributes the coverage of a package to every test which runs its
# code, not only to the tests of the package itself.
UNIT_TEST_TIMEOUT ?= 30m

test-unit: | $(BUILD_DIR) ## Run the unit tests
	$(GO) test -ldflags '$(LDVARS)' -tags '$(BUILDTAGS)' -race -v -shuffle=on -timeout $(UNIT_TEST_TIMEOUT) \
		-coverpkg=./internal/...,./api/...,./cmd/... -coverprofile=$(BUILD_DIR)/coverage.out \
		./internal/... ./api/... ./cmd/...
	$(GO) tool cover -html $(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

# The envtest binaries follow the Kubernetes version of the vendored
# k8s.io/api, v0.37.x runs against 1.37.x.
ENVTEST_K8S_VERSION ?= $(shell $(GO) list -m -f '{{.Version}}' k8s.io/api | awk -F'[v.]' '{printf "1.%d.x", $$3}')
INTEGRATION_TEST_TIMEOUT ?= 15m

$(BUILD_DIR)/setup-envtest: | $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) GOFLAGS= CGO_ENABLED=0 $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)

# SPO_INTEGRATION_REQUIRED fails the tests instead of skipping them without
# the envtest binaries.
.PHONY: test-integration
test-integration: $(BUILD_DIR)/setup-envtest ## Run the controller integration tests against envtest
	assets="$$($(BUILD_DIR)/setup-envtest use -p path --bin-dir $(abspath $(BUILD_DIR))/envtest $(ENVTEST_K8S_VERSION))" && \
	if [ -z "$$assets" ]; then \
		echo "setup-envtest found no envtest binaries for Kubernetes $(ENVTEST_K8S_VERSION)" >&2; \
		exit 1; \
	fi && \
	KUBEBUILDER_ASSETS="$$assets" SPO_INTEGRATION_REQUIRED=true \
		$(GO) test -tags 'integration $(BUILDTAGS)' -race -v -count=1 -timeout $(INTEGRATION_TEST_TIMEOUT) \
		./internal/pkg/integration/...

# FUZZ_TARGETS lists the fuzz tests as package:FuzzName, by default every
# func Fuzz of the test files below internal, cmd and api. go test fuzzes only
# one target per run, so test-fuzz runs them one after another.
FUZZ_TIME ?= 30s
FUZZ_TARGETS ?= $(shell grep -rHo --include='*_test.go' '^func Fuzz[A-Za-z0-9_]*' internal cmd api | \
	sed -E 's;^(.*)/[^/]+_test\.go:func (Fuzz[A-Za-z0-9_]*)$$;./\1:\2;' | sort)

.PHONY: test-fuzz
test-fuzz: ## Run every fuzz target for FUZZ_TIME, one target per go test run
	@set -e; for target in $(FUZZ_TARGETS); do \
		pkg=$${target%%:*}; fuzz=$${target##*:}; \
		echo "Fuzzing $$fuzz in $$pkg for $(FUZZ_TIME)"; \
		$(GO) test -tags '$(BUILDTAGS)' -run '^$$' -fuzz "^$$fuzz$$" -fuzztime $(FUZZ_TIME) $$pkg; \
	done

# E2E_TEST_BINARY is a prebuilt e2e test binary (go test -c -tags e2e ./test) to run
# instead of building the tests. CI builds it outside of the test VMs, where
# compiling the tests takes more than 10 minutes. The binary runs in ./test,
# like go test runs it, and ARGS are test binary flags then (-test.run=...).
E2E_TEST_BINARY ?=
E2E_TEST_PACKAGE := $(GO_PROJECT)/test
# E2E_TEST_SKIP is a regular expression of the e2e tests to skip, see -skip in
# go help testflag.
E2E_TEST_SKIP ?=
E2E_TEST_SKIP_FLAG := $(if $(E2E_TEST_SKIP),-test.skip='$(E2E_TEST_SKIP)')
# E2E_SKIP_FLAKY_TESTS skips the quarantined test cases in test-e2e, see
# doc/hacking.md. They only run through test-flaky-e2e, which retries them.
# E2E_SKIP_FLAKY_TESTS=false runs them in test-e2e as well, without retries.
E2E_SKIP_FLAKY_TESTS ?= true

.PHONY: test-e2e
test-e2e: ## Run the end-to-end tests
ifeq ($(E2E_TEST_BINARY),)
	CGO_LDFLAGS= \
	E2E_SKIP_FLAKY_TESTS=$(E2E_SKIP_FLAKY_TESTS) \
	$(GO) test -tags e2e -parallel 1 -timeout 60m -count=1 ./test -v $(E2E_TEST_SKIP_FLAG) $(ARGS)
else
	cd test && \
	E2E_SKIP_FLAKY_TESTS=$(E2E_SKIP_FLAKY_TESTS) \
	$(abspath $(E2E_TEST_BINARY)) -test.parallel=1 -test.timeout=60m -test.count=1 -test.v \
		$(E2E_TEST_SKIP_FLAG) $(ARGS)
endif

# Failed flaky tests get one retry. gotestsum records the retries in the JUnit
# report, so a test which only passes on retry stays visible. The suite method
# is selected with -run, since gotestsum appends the package after the go test
# flags and go test stops parsing packages at the first unknown flag. A
# prebuilt binary runs as raw command, to which gotestsum appends the
# -test.run flag and the package of the retried tests, which the binary
# ignores.
#
# E2E_RETRY_RUN selects the tests, the quarantined test cases by default. The
# nightly flake analysis runs the whole suite with retries through
# E2E_RETRY_RUN=^TestSuite and a longer E2E_RETRY_TIMEOUT, see
# test/ci/junit-flakes.py.
E2E_RETRY_RUN ?= ^TestSuite$$/^TestSecurityProfilesOperator_Flaky$$
E2E_RETRY_TIMEOUT ?= 30m

.PHONY: test-flaky-e2e
test-flaky-e2e: $(BUILD_DIR) ## Only run the quarantined end-to-end tests
ifeq ($(E2E_TEST_BINARY),)
	CGO_LDFLAGS= \
	E2E_SKIP_FLAKY_TESTS=false \
	$(GOTESTSUM) \
		--format standard-verbose \
		--junitfile $(BUILD_DIR)/junit-flaky-e2e.xml \
		--packages ./test \
		--rerun-fails=1 \
		-- -tags e2e -parallel 1 -timeout $(E2E_RETRY_TIMEOUT) -count=1 -run '$(E2E_RETRY_RUN)' \
		$(E2E_TEST_SKIP_FLAG)
else
	cd test && \
	CGO_LDFLAGS= \
	E2E_SKIP_FLAKY_TESTS=false \
	$(GOTESTSUM) \
		--format standard-verbose \
		--junitfile $(abspath $(BUILD_DIR))/junit-flaky-e2e.xml \
		--rerun-fails=1 \
		--raw-command \
		-- $(GO) tool test2json -t -p $(E2E_TEST_PACKAGE) \
		$(abspath $(E2E_TEST_BINARY)) -test.v=test2json -test.parallel=1 -test.timeout=$(E2E_RETRY_TIMEOUT) \
		-test.count=1 -test.run='$(E2E_RETRY_RUN)' $(E2E_TEST_SKIP_FLAG)
endif

.PHONY: test-spoc-e2e
test-spoc-e2e: $(BUILD_DIR)/$(CLI_BINARY) ## Run the spoc end-to-end tests
	$(GO) test -v -timeout 20m ./test/spoc $(ARGS)

manifests: $(BUILD_DIR)/kubernetes-split-yaml $(BUILD_DIR)/kustomize ## Generate the CRD manifests
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/spod/...' output:crd:stdout" "deploy/base-crds/crds/securityprofilesoperatordaemon.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/secprofnodestatus/...' output:crd:stdout" "deploy/base-crds/crds/securityprofilenodestatus.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/seccompprofile/...' output:crd:stdout" "deploy/base-crds/crds/seccompprofile.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/selinuxprofile/...' output:crd:stdout" "deploy/base-crds/crds/selinuxpolicy.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/profilebinding/...' output:crd:stdout" "deploy/base-crds/crds/profilebinding.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/profilerecording/...' output:crd:stdout" "deploy/base-crds/crds/profilerecording.yaml"
	./hack/sort-crds.sh "$(CONTROLLER_GEN_CMD) $(CRD_OPTIONS) paths='./api/apparmorprofile/...' output:crd:stdout" "deploy/base-crds/crds/apparmorprofile.yaml"

generate: ## Generate the deepcopy code and the RBAC roles
	$(CONTROLLER_GEN_CMD) object:headerFile="hack/boilerplate/boilerplate.go.txt" paths="./api/..."
	$(CONTROLLER_GEN_CMD) rbac:roleName=security-profiles-operator paths="./internal/pkg/manager/..." output:rbac:stdout > deploy/base/role.yaml
	$(CONTROLLER_GEN_CMD) rbac:roleName=spod paths="./internal/pkg/daemon/..." output:rbac:stdout >> deploy/base/role.yaml
	$(CONTROLLER_GEN_CMD) rbac:roleName=spo-webhook paths="./internal/pkg/webhooks/..." output:rbac:stdout >> deploy/base/role.yaml

## Bundle packaging begins here
## read more at https://sdk.operatorframework.io/docs/olm-integration/tutorial-bundle/

# The tool binaries carry their version in the file name, so a version bump
# downloads the new release. The unversioned symlinks serve the PATH of the OLM
# workflow and hack/attest-images.sh.
OPERATOR_SDK = $(BUILD_DIR)/operator-sdk-$(OPERATOR_SDK_VERSION)

.PHONY: operator-sdk
operator-sdk: $(OPERATOR_SDK) ## Download operator-sdk locally if necessary.
	ln -sf $(notdir $(OPERATOR_SDK)) $(BUILD_DIR)/operator-sdk

$(OPERATOR_SDK): | $(BUILD_DIR)
	curl -sSfL --retry 5 --retry-delay 3 -o $@.download \
		https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_$(TOOLS_PLATFORM)
	echo "$(OPERATOR_SDK_SHA256_$(TOOLS_PLATFORM))  $@.download" | $(SHA256SUM) -c -
	chmod +x $@.download
	mv $@.download $@

# The channels and the default channel of the bundle. Override them as make
# variables or from the environment, like `make bundle CHANNELS=fast,stable`.
CHANNELS ?= stable
DEFAULT_CHANNEL ?= stable
BUNDLE_METADATA_OPTS ?= --channels=$(CHANNELS) --default-channel=$(DEFAULT_CHANNEL)

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
	# The skipRange gets bumped only for the bundle. Keep a copy instead of
	# using git restore, which would also drop uncommitted changes to the file.
	cp deploy/base/clusterserviceversion.yaml $(BUILD_DIR)/clusterserviceversion.yaml.orig
	$(SED) "s/\(olm.skipRange: '>=.*\)<.*'/\1<$(VERSION)'/" deploy/base/clusterserviceversion.yaml
	$(SED) "s/\(\"name\": \"security-profiles-operator.v\).*\"/\1$(VERSION)\"/" deploy/catalog-preamble.json
	$(SED) "s/\(\"skipRange\": \">=.*\)<.*\"/\1<$(VERSION)\"/" deploy/catalog-preamble.json
	# operator-sdk never removes files, so start clean to not ship stale manifests
	rm -rf ./bundle/manifests ./bundle/metadata
	cat $(OLM_EXAMPLES) $(BUNDLE_OPERATOR_MANIFEST) deploy/base/clusterserviceversion.yaml | $(OPERATOR_SDK) generate bundle -q --overwrite $(BUNDLE_SA_OPTS) --version $(VERSION) $(BUNDLE_METADATA_OPTS)
	mv $(BUILD_DIR)/clusterserviceversion.yaml.orig deploy/base/clusterserviceversion.yaml
	mkdir -p ./bundle/tests/scorecard
	cp deploy/bundle-test-config.yaml ./bundle/tests/scorecard/config.yaml
	$(OPERATOR_SDK) bundle validate ./bundle

# The build context of bundle.Dockerfile, with the bundle files at the same
# paths as in the repository.
BUNDLE_DIR = $(BUILD_DIR)/bundle

# Copy the files of the bundle image into $(BUNDLE_DIR) with fixed file modes,
# so that hack/image-cross.sh builds it reproducibly whatever modes the
# checkout created.
.PHONY: bundle-context
bundle-context: ## Copy the bundle files into the build context of bundle.Dockerfile.
	rm -rf $(BUNDLE_DIR)
	mkdir -p $(BUNDLE_DIR)/bundle/tests
	cp -R bundle/manifests bundle/metadata $(BUNDLE_DIR)/bundle/
	cp -R bundle/tests/scorecard $(BUNDLE_DIR)/bundle/tests/
	find $(BUNDLE_DIR) -type d -exec chmod 0755 {} +
	find $(BUNDLE_DIR) -type f -exec chmod 0644 {} +

.PHONY: bundle-build
bundle-build: bundle-context ## Build the bundle image.
	$(CONTAINER_RUNTIME) build -f bundle.Dockerfile -t $(BUNDLE_IMG) $(BUNDLE_DIR)

.PHONY: verify-bundle
verify-bundle: bundle ## Verify the bundle doesn't alter the state of the tree
	git diff --exit-code -I'^    createdAt: ' -- bundle bundle.Dockerfile
	test -z "$$(git ls-files --others --exclude-standard -- bundle bundle.Dockerfile)"

OPM = $(BUILD_DIR)/opm-$(OPM_VERSION)

.PHONY: opm
opm: $(OPM) ## Download opm locally if necessary.
	ln -sf $(notdir $(OPM)) $(BUILD_DIR)/opm

$(OPM): | $(BUILD_DIR)
	curl -sSfL --retry 5 --retry-delay 3 -o $@.download \
		https://github.com/operator-framework/operator-registry/releases/download/$(OPM_VERSION)/$(subst _,-,$(TOOLS_PLATFORM))-opm
	echo "$(OPM_SHA256_$(TOOLS_PLATFORM))  $@.download" | $(SHA256SUM) -c -
	chmod +x $@.download
	mv $@.download $@

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(PROJECT)-catalog:v$(VERSION)

# The repository the catalog references the bundle from, if it differs from
# the one it is rendered from, for example the production registry the staging
# bundle gets promoted to. BUNDLE_IMGS has to be a single bundle pinned by
# digest then, which promotion keeps.
CATALOG_BUNDLE_REPO ?=
BUNDLE_REPO = $(firstword $(subst @, ,$(BUNDLE_IMGS)))

# The base and builder image of the catalog, opm defaults to its latest tag.
# Bump together with OPM_VERSION.
OPM_IMAGE ?= quay.io/operator-framework/opm:$(OPM_VERSION)@sha256:b32d3891616662620da08d7f0ec42c2e69fa2de43427dc975d35b12f7a969a0f

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# The build context of catalog.Dockerfile, with the file-based catalog in
# configs.
CATALOG_DIR = $(BUILD_DIR)/catalog

# Render the file-based catalog of the bundle images into $(CATALOG_DIR). The
# catalog only depends on the bundles, the preamble and opm, with fixed file
# modes, so that hack/image-cross.sh builds it reproducibly. The catalog gets
# rendered a second time from its own directory, so that opm writes the
# preamble as well and sorts the related images after the CATALOG_BUNDLE_REPO
# rewrite, the same as a render from CATALOG_BUNDLE_REPO. That render pulls no
# images, so it needs no OPM_EXTRA_ARGS.
.PHONY: catalog-context
catalog-context: opm ## Render the file-based catalog into the build context of catalog.Dockerfile.
	rm -rf $(CATALOG_DIR) $(CATALOG_DIR).opm
	mkdir -p $(CATALOG_DIR)/configs $(CATALOG_DIR).opm
	cp deploy/catalog-preamble.json $(CATALOG_DIR)/configs/security-profiles-operator-catalog.json
	XDG_RUNTIME_DIR=$(abspath $(CATALOG_DIR).opm) $(OPM) $(OPM_EXTRA_ARGS) render $(BUNDLE_IMGS) >> $(CATALOG_DIR)/configs/security-profiles-operator-catalog.json
ifneq ($(CATALOG_BUNDLE_REPO),)
	@case "$(BUNDLE_IMGS)" in *,*) echo "CATALOG_BUNDLE_REPO needs a single bundle image" >&2; exit 1;; *@sha256:*) ;; *) echo "CATALOG_BUNDLE_REPO needs BUNDLE_IMGS pinned by digest" >&2; exit 1;; esac
	$(SED) 's#"$(BUNDLE_REPO)@sha256:#"$(CATALOG_BUNDLE_REPO)@sha256:#g' $(CATALOG_DIR)/configs/security-profiles-operator-catalog.json
	! grep -F '"$(BUNDLE_REPO)@' $(CATALOG_DIR)/configs/security-profiles-operator-catalog.json
endif
	XDG_RUNTIME_DIR=$(abspath $(CATALOG_DIR).opm) $(OPM) render $(CATALOG_DIR)/configs > $(CATALOG_DIR).opm/catalog.json
	mv $(CATALOG_DIR).opm/catalog.json $(CATALOG_DIR)/configs/security-profiles-operator-catalog.json
	chmod 0755 $(CATALOG_DIR)/configs
	chmod 0644 $(CATALOG_DIR)/configs/security-profiles-operator-catalog.json
	rm -rf $(CATALOG_DIR).opm

# This target uses the file-based catalog format (https://olm.operatorframework.io/docs/reference/file-based-catalogs/)
.PHONY: catalog-build
catalog-build: catalog-context ## Build a catalog image.
	$(CONTAINER_RUNTIME) build -f catalog.Dockerfile --build-arg OPM_IMAGE=$(OPM_IMAGE) -t $(CATALOG_IMG) $(CATALOG_DIR)

## OpenShift-only
## These targets are meant to make development in OpenShift easier.

.PHONY: openshift-user
openshift-user: ## Determine the OpenShift user for the image registry login
ifeq ($(shell oc whoami 2> /dev/null),kube:admin)
	$(eval OPENSHIFT_USER = kubeadmin)
else
	$(eval OPENSHIFT_USER = $(shell oc whoami))
endif

.PHONY: set-openshift-image-params
set-openshift-image-params: ## Use Dockerfile.ubi for the OpenShift images
	$(eval DOCKERFILE = Dockerfile.ubi)

.PHONY: _push-image-openshift-dev
_push-image-openshift-dev: ## Push IMAGE to the OpenShift image registry
	@echo "Exposing the default route to the image registry"
	@oc patch configs.imageregistry.operator.openshift.io/cluster --patch '{"spec":{"defaultRoute":true}}' --type=merge
	@echo "Pushing image $(IMAGE) to the image registry"
ifeq ($(CONTAINER_RUNTIME),docker)
	@IMAGE_REGISTRY_HOST=$$(oc get route default-route -n openshift-image-registry --template='{{ .spec.host }}'); \
		$(CONTAINER_RUNTIME) login $(LOGIN_PUSH_OPTS) -u $(OPENSHIFT_USER) -p $(shell oc whoami -t) $${IMAGE_REGISTRY_HOST}; \
		$(CONTAINER_RUNTIME) tag $(LOGIN_PUSH_OPTS) $(IMAGE) $${IMAGE_REGISTRY_HOST}/openshift/$(IMAGE); \
		$(CONTAINER_RUNTIME) push $(LOGIN_PUSH_OPTS) $${IMAGE_REGISTRY_HOST}/openshift/$(IMAGE)
else
	@IMAGE_REGISTRY_HOST=$$(oc get route default-route -n openshift-image-registry --template='{{ .spec.host }}'); \
		$(CONTAINER_RUNTIME) login $(LOGIN_PUSH_OPTS) -u $(OPENSHIFT_USER) -p $(shell oc whoami -t) $${IMAGE_REGISTRY_HOST}; \
		$(CONTAINER_RUNTIME) push $(LOGIN_PUSH_OPTS) localhost/$(IMAGE) $${IMAGE_REGISTRY_HOST}/openshift/$(IMAGE)

endif

.PHONY: push-prebuilt-image-openshift-dev
push-prebuilt-image-openshift-dev: set-openshift-image-params openshift-user _push-image-openshift-dev ## Push a pre-built image to the OpenShift image registry
	@echo "Pushed a pre-built image to image registry"

.PHONY: push-openshift-dev
push-openshift-dev: set-openshift-image-params openshift-user image _push-image-openshift-dev ## Build the image and push it to the OpenShift image registry
	@echo "Built image and pushed to image registry"
.PHONY: do-deploy-openshift-dev
do-deploy-openshift-dev: ## Deploy deploy/openshift-dev.yaml into the current OpenShift cluster
	@echo "Deploying"
	oc apply -f deploy/openshift-dev.yaml
	@echo "Setting triggers to track image"
	oc set triggers -n security-profiles-operator deployment/security-profiles-operator --from-image openshift/security-profiles-operator:latest -c security-profiles-operator

.PHONY: deploy-openshift-dev
deploy-openshift-dev: push-openshift-dev do-deploy-openshift-dev ## Build, push and deploy the operator for development into OpenShift

.PHONY: deploy-prebuilt-openshift-dev
deploy-prebuilt-openshift-dev: push-prebuilt-image-openshift-dev do-deploy-openshift-dev ## Push a pre-built image and deploy the operator for development into OpenShift

.PHONY: deploy
deploy: ## Deploy the operator with IMAGE into the current kubectl context
	mkdir -p build/deploy && cp deploy/operator.yaml build/deploy/
	$(SED) "s#us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator:latest#$(IMAGE)#g" build/deploy/operator.yaml
	$(SED) "s#replicas: 3#replicas: 1#g" build/deploy/operator.yaml
	kubectl apply -f build/deploy/operator.yaml
	kubectl apply -f examples/config.yaml
