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
BUILD_PATH := $(shell pwd)/$(BUILD_DIR)

BUILDTAGS := netgo
LDFLAGS := -s -w -linkmode external -extldflags "-static"

all: $(BUILD_DIR)/$(PROJECT)

$(BUILD_PATH):
	mkdir -p $(BUILD_PATH)

$(BUILD_DIR)/$(PROJECT): $(BUILD_PATH)
	$(GO) build -ldflags '$(LDFLAGS)' -tags '$(BUILDTAGS)' -o $@ ./cmd/seccomp-operator

.PHONY: clean
clean:
	rm -rf $(BUILD_PATH)

.PHONY: go-mod
go-mod:
	export GO111MODULE=on \
		$(GO) mod tidy && \
		$(GO) mod verify

.PHONY: verify-boilerplate
verify-boilerplate: $(BUILD_PATH)/verify_boilerplate.py
	$(BUILD_PATH)/verify_boilerplate.py --boilerplate-dir hack/boilerplate

$(BUILD_PATH)/verify_boilerplate.py: $(BUILD_PATH)
	curl -sfL https://raw.githubusercontent.com/kubernetes/repo-infra/v0.0.6/hack/verify_boilerplate.py \
		-o $(BUILD_PATH)/verify_boilerplate.py
	chmod +x $(BUILD_PATH)/verify_boilerplate.py
