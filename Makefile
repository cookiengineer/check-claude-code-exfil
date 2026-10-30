SHELL := /bin/sh

BINARY     := check-claude-code-exfil
BUILD_DIR  := build
SOURCE_DIR := source
PACKAGE    := ./cmds/check-claude-code-exfil

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
PLATFORM_TARGETS := $(addprefix build/,$(PLATFORMS))

.PHONY: all build test vet fmt clean $(PLATFORM_TARGETS)

all: build

build: $(PLATFORM_TARGETS)

define build_platform
build/$(1)/$(2):
	@set -eu; \
	os='$(1)'; \
	arch='$(2)'; \
	ext=''; \
	if [ "$$$$os" = "windows" ]; then ext='.exe'; fi; \
	out="$(CURDIR)/$(BUILD_DIR)/$(BINARY)_$$$${os}_$$$${arch}$$$${ext}"; \
	mkdir -p "$(CURDIR)/$(BUILD_DIR)"; \
	printf 'building %s/%s -> %s\n' "$$$$os" "$$$$arch" "$$$$out"; \
	cd "$(CURDIR)/$(SOURCE_DIR)" && \
		CGO_ENABLED=0 GOOS="$$$$os" GOARCH="$$$$arch" \
		go build -trimpath -ldflags="-s -w" -o "$$$$out" $(PACKAGE)
endef

$(foreach platform,$(PLATFORMS),$(eval $(call build_platform,$(word 1,$(subst /, ,$(platform))),$(word 2,$(subst /, ,$(platform))))))

test:
	cd "$(CURDIR)/$(SOURCE_DIR)" && go test ./...

vet:
	cd "$(CURDIR)/$(SOURCE_DIR)" && go vet ./...

fmt:
	cd "$(CURDIR)/$(SOURCE_DIR)" && gofmt -w $$(find . -name '*.go' -type f)

check: vet test

clean:
	rm -rf "$(CURDIR)/$(BUILD_DIR)"
