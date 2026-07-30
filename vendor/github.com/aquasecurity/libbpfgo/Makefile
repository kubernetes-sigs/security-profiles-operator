
.ONESHELL:
SHELL = /bin/bash

BASEDIR = $(abspath ./)

OUTPUT = ./output
SELFTEST = ./selftest

CLANG := clang
CC := $(CLANG)
GO := go
VAGRANT := vagrant
CLANG_FMT := clang-format-14
GIT := $(shell which git || /bin/false)
REVIVE := revive
STATICCHECK := staticcheck
GOIMPORTS_REVISER := goimports-reviser
ERRCHECK := errcheck
GOIMPORTS_COMPANY_PREFIXES := "github.com/aquasecurity"
GOIMPORTS_PROJECT := "github.com/aquasecurity/libbpfgo"
GOIMPORTS_EXCLUDES := ".git/,libbpf/,output/"
REVIVE_EXCLUDES := "libbpf/...,output/..."
PKGCONFIG := pkg-config

HOSTOS = $(shell uname)
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')


# libbpf

LIBBPF_SRC = $(abspath ./libbpf/src)
LIBBPF_INCLUDE_UAPI = $(abspath ./libbpf/include/uapi)
LIBBPF_OBJ = $(abspath ./$(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))

CFLAGS = -g -O2 -Wall -fpie -I$(abspath $(OUTPUT))
LDFLAGS =

# golang

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT)) -I$(LIBBPF_INCLUDE_UAPI)"
CGO_LDFLAGS_STATIC = "$(shell PKG_CONFIG_PATH=$(LIBBPF_OBJDIR) $(PKGCONFIG) --static --libs libbpf)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'
GO_LINT_ENV = CC=$(CLANG) CGO_CFLAGS=$(CGO_CFLAGS_STATIC) CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC)

CGO_CFLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "$(shell $(PKGCONFIG) --shared --libs libbpf)"

# default == shared lib from OS package

all: libbpfgo-static
test: libbpfgo-static-test

# libbpf uapi

.PHONY: libbpf-uapi

libbpf-uapi: $(LIBBPF_SRC)
# UAPI headers can be installed by a different package so they're not installed
# in by (libbpf) install rule.
	UAPIDIR=$(LIBBPF_DESTDIR) \
		$(MAKE) -C $(LIBBPF_SRC) install_uapi_headers

# libbpfgo test object

libbpfgo-test-bpf-static: libbpfgo-static	# needed for serialization
	$(MAKE) -C $(SELFTEST)/build

libbpfgo-test-bpf-dynamic: libbpfgo-dynamic	# needed for serialization
	$(MAKE) -C $(SELFTEST)/build

libbpfgo-test-bpf-clean:
	$(MAKE) -C $(SELFTEST)/build clean

# libbpf: shared

libbpfgo-dynamic: $(OUTPUT)/libbpf
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
		$(GO) build .

libbpfgo-dynamic-test: libbpfgo-test-bpf-dynamic
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_DYN) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_DYN) \
		sudo -E $(GO) test .

# libbpf: static

libbpfgo-static: libbpf-uapi $(LIBBPF_OBJ) 
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		.

libbpfgo-static-test: libbpfgo-test-bpf-static
	sudo env PATH=$(PATH) \
		CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO) test \
		-v -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		.

# static libbpf generation for the git submodule

.PHONY: libbpf-static
libbpf-static: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	CC="$(CC)" CFLAGS="$(CFLAGS)" LD_FLAGS="$(LDFLAGS)" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		LIBDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= UAPIDIR= install

$(LIBBPF_SRC):
ifeq ($(wildcard $@), )
	echo "INFO: updating submodule 'libbpf'"
	$(GIT) submodule update --init --recursive
endif

# selftests

# To set a minimum Go version requirement for a specific selftest:
# 1. Create a .go-version file in the selftest directory (e.g., selftest/my-test/.go-version)
# 2. Add the minimum version in major.minor format (e.g., "1.21" for Go 1.21.0 or higher)
# 3. The selftest will be automatically skipped if the current Go version is lower
# Example: echo "1.21" > selftest/my-advanced-test/.go-version

# current Go version (major.minor format)
GO_VERSION := $(shell $(GO) version | sed -n 's/.*go\([0-9]*\.[0-9]*\).*/\1/p')
SELFTESTS = $(shell find $(SELFTEST) -mindepth 1 -maxdepth 1 -type d ! -name 'common' ! -name 'build')

define FOREACH
	SELFTESTERR=0; \
	FAILED_TESTS=""; \
	for DIR in $(SELFTESTS); do \
		echo "INFO: entering $$DIR..."; \
		if [ -f "$$DIR/.go-version" ]; then \
			REQUIRED_VERSION=$$(cat "$$DIR/.go-version"); \
			if ! printf '%s\n%s\n' "$$REQUIRED_VERSION" "$(GO_VERSION)" | sort -V -C; then \
				echo "INFO: skipping $$DIR (requires Go $$REQUIRED_VERSION, current: $(GO_VERSION))"; \
				continue; \
			fi; \
		fi; \
		$(MAKE) -j1 -C $$DIR $(1) || { SELFTESTERR=1; FAILED_TESTS="$$FAILED_TESTS $$DIR"; }; \
	done; \
	if [ $$SELFTESTERR -eq 1 ]; then \
		echo "ERROR: The following selftests failed:$$FAILED_TESTS"; \
		exit 1; \
	fi
endef

.PHONY: selftest
.PHONY: selftest-static
.PHONY: selftest-dynamic
.PHONY: selftest-run
.PHONY: selftest-static-run
.PHONY: selftest-dynamic-run
.PHONY: selftest-clean

selftest: selftest-static

selftest-static:
	$(call FOREACH, main-static)
selftest-dynamic:
	$(call FOREACH, main-dynamic)

selftest-run: selftest-static-run

selftest-static-run:
	$(call FOREACH, run-static)
selftest-dynamic-run:
	$(call FOREACH, run-dynamic)

selftest-clean:
	$(call FOREACH, clean)

# go module maintenance

GO_MODULES = $(shell find . -name "go.mod" -type f -not -path "./go.mod" | sort)

define FOREACH_MODULE
	GOERR=0; FAILED=""; \
	echo "Running in root module..."; \
	$(1) || { GOERR=1; FAILED="$$FAILED ."; }; \
	for MOD_FILE in $(GO_MODULES); do \
		MOD_DIR=$$(dirname "$$MOD_FILE"); \
		echo "Running in $$MOD_DIR..."; \
		(cd "$$MOD_DIR" && $(1)) || { GOERR=1; FAILED="$$FAILED $$MOD_DIR"; }; \
	done; \
	if [ $$GOERR -eq 1 ]; then \
		echo "ERROR: failed in:$$FAILED"; \
		exit 1; \
	fi
endef

.PHONY: go-tidy
.PHONY: go-get

go-tidy:
	$(call FOREACH_MODULE, $(GO) mod tidy)

# Usage: make go-get <package>[@version] ...
# Prevent make from treating package arguments as targets.
ifneq ($(filter go-get,$(MAKECMDGOALS)),)
go-get-args := $(filter-out go-get,$(MAKECMDGOALS))
ifneq ($(strip $(go-get-args)),)
$(go-get-args):
	@:
endif
endif

go-get:
	@args="$(filter-out go-get,$(MAKECMDGOALS))"; \
	if [ -z "$$args" ]; then \
		echo "Usage: make go-get <package>[@version]..."; \
		exit 1; \
	fi
	$(call FOREACH_MODULE, $(GO) get $(filter-out go-get,$(MAKECMDGOALS)))

# vagrant

VAGRANT_DIR = $(abspath ./builder)

.PHONY: vagrant-up
.PHONY: vagrant-destroy
.PHONY: vagrant-halt
.PHONY: vagrant-ssh

vagrant-up: .vagrant-up
vagrant-destroy: .vagrant-destroy
vagrant-halt: .vagrant-halt
vagrant-ssh: .vagrant-ssh

.vagrant-%:
	VAGRANT_VAGRANTFILE=$(VAGRANT_DIR)/Vagrantfile-ubuntu \
		ARCH=$(ARCH) \
		HOSTOS=$(HOSTOS) \
		$(VAGRANT) $*

#
# code check and linting
#

# fmt-check

C_FILES_TO_BE_CHECKED = $(shell find -regextype posix-extended -regex '.*\.(h|c)' ! -regex '.*(libbpf|output)\/.*' | xargs)

fmt-check:
	@errors=0
	echo "Checking C and eBPF files and headers formatting..."
	$(CLANG_FMT) --dry-run -i $(C_FILES_TO_BE_CHECKED) > /tmp/check-c-fmt 2>&1
	clangfmtamount=$$(cat /tmp/check-c-fmt | wc -l)
	if [[ $$clangfmtamount -ne 0 ]]; then
		head -n30 /tmp/check-c-fmt
		errors=1
	fi
	rm -f /tmp/check-c-fmt
#
	if [[ $$errors -ne 0 ]]; then
		echo
		echo "Please fix formatting errors above!"
		echo "Use: $(MAKE) fmt-fix target".
		echo
		exit 1
	fi

# fmt-fix

fmt-fix:
	@echo "Fixing C and eBPF files and headers formatting..."
	$(CLANG_FMT) -i --verbose $(C_FILES_TO_BE_CHECKED)

# lint-check

.PHONY: lint-check
lint-check: libbpf-static
#
	@errors=0
	echo "Linting golang code..."
	echo "Running revive..."
	if ! $(GO_LINT_ENV) $(REVIVE) -config .revive.toml -exclude $(REVIVE_EXCLUDES) ./...; then
		echo "FAIL: revive"
		errors=1
	fi
	echo "Running staticcheck..."
	if ! $(GO_LINT_ENV) $(STATICCHECK) ./...; then
		echo "FAIL: staticcheck"
		errors=1
	fi
	echo "Running goimports-reviser..."
	if ! $(GO_LINT_ENV) $(GOIMPORTS_REVISER) \
		-output stdout \
		-list-diff \
		-set-exit-status \
		-company-prefixes $(GOIMPORTS_COMPANY_PREFIXES) \
		-project-name $(GOIMPORTS_PROJECT) \
		-excludes $(GOIMPORTS_EXCLUDES) \
		./...; then
		echo "FAIL: goimports-reviser"
		errors=1
	fi
	echo "Running errcheck..."
	if ! $(GO_LINT_ENV) $(ERRCHECK) ./...; then
		echo "FAIL: errcheck"
		errors=1
	fi
	if [[ $$errors -ne 0 ]]; then
		echo
		echo "Please fix lint errors above!"
		exit 1
	fi

# output

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/libbpf:
	mkdir -p $(OUTPUT)/libbpf

# cleanup

clean: selftest-clean libbpfgo-test-bpf-clean
	rm -rf $(OUTPUT)
