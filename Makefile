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

PROJECT := seccomp-operator
BUILD_DIR := build

DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date -u "$(DATE_FMT)")
endif

GIT_COMMIT := $(shell git rev-parse HEAD 2> /dev/null || echo unknown)
GIT_TREE_STATE := $(if $(shell git status --porcelain --untracked-files=no),dirty,clean)
GIT_VERSION := $(shell git describe --abbrev=0 2>/dev/null || echo 0.0.0)

BUILDTAGS := netgo
BUILD_FILES := $(shell find . -type f -name '*.go' -or -name '*.mod' -or -name '*.sum' -not -name '*_test.go')
GO_PROJECT := sigs.k8s.io/$(PROJECT)
LDVARS := \
	-X $(GO_PROJECT)/internal/pkg/version.buildDate=$(BUILD_DATE) \
	-X $(GO_PROJECT)/internal/pkg/version.gitCommit=$(GIT_COMMIT) \
	-X $(GO_PROJECT)/internal/pkg/version.gitTreeState=$(GIT_TREE_STATE) \
	-X $(GO_PROJECT)/internal/pkg/version.gitVersion=$(GIT_VERSION)
LDFLAGS := -s -w -linkmode external -extldflags "-static" $(LDVARS)

CONTAINER_RUNTIME ?= docker
IMAGE ?= $(PROJECT):latest

GOLANGCI_LINT_VERSION = v1.30.0
REPO_INFRA_VERSION = v0.0.10

# Utility targets

all: $(BUILD_DIR)/$(PROJECT) ## Build the seccomp-operator binary

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
	$(GO) build -ldflags '$(LDFLAGS)' -tags '$(BUILDTAGS)' -o $@ ./cmd/seccomp-operator

.PHONY: clean
clean: ## Clean the build directory
	rm -rf $(BUILD_DIR)

.PHONY: go-mod
go-mod: ## Cleanup and verify go modules
	export GO111MODULE=on \
		$(GO) mod tidy && \
		$(GO) mod verify

.PHONY: default-profiles
default-profiles: ## Generate the default profiles
	$(GO) run ./profiles

.PHONY: image
image: ## Build the container image
	$(CONTAINER_RUNTIME) build --build-arg version=$(GIT_VERSION) -t $(IMAGE) .

# Verification targets

.PHONY: verify
verify: verify-boilerplate verify-go-mod verify-go-lint verify-default-profiles ## Run all verification targets

.PHONY: verify-boilerplate
verify-boilerplate: $(BUILD_DIR)/verify_boilerplate.py ## Verify the boilerplate headers for all files
	$(BUILD_DIR)/verify_boilerplate.py --boilerplate-dir hack/boilerplate

$(BUILD_DIR)/verify_boilerplate.py: $(BUILD_DIR)
	curl -sfL https://raw.githubusercontent.com/kubernetes/repo-infra/$(REPO_INFRA_VERSION)/hack/verify_boilerplate.py \
		-o $(BUILD_DIR)/verify_boilerplate.py
	chmod +x $(BUILD_DIR)/verify_boilerplate.py

.PHONY: verify-go-mod
verify-go-mod: go-mod ## Verify the go modules
	hack/tree-status

.PHONY: verify-default-profiles
verify-default-profiles: default-profiles ## Verify the generated default profiles
	hack/tree-status

.PHONY: verify-go-lint
verify-go-lint: $(BUILD_DIR)/golangci-lint ## Verify the golang code by linting
	$(BUILD_DIR)/golangci-lint run

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
	$(GO) test -ldflags '$(LDVARS)' -v -test.coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GO) tool cover -html $(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

.PHONY: test-e2e
test-e2e: ## Run the end-to-end tests
	$(GO) test -timeout 20m -tags e2e -count=1 ./test/... -v
