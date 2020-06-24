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
	$(GO) build -ldflags '$(LDFLAGS)' -tags '$(BUILDTAGS)' -o $@

.PHONY: clean
clean:
	rm -rf $(BUILD_PATH)

.PHONY: go-mod
go-mod:
	export GO111MODULE=on \
		$(GO) mod tidy && \
		$(GO) mod verify
