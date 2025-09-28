# =======================
# Project: gmrtd (mobile + tests)
# =======================

# -------- Repo / Packages --------
MODULE              ?= github.com/gmrtd/gmrtd
PKG_MOBILE          ?= $(MODULE)/mobile

# Package lists (exclude vendor; exclude /cmd/gmrtd-reader from unit tests by default)
PKGS			 = $(shell go list ./... | grep -vE '/vendor$$')
PKGS_NO_CMD		= $(shell go list ./... | grep -vE '/vendor$$|/cmd/gmrtd-reader$$')

# -------- Output --------
IOS_OUT             ?= dist/ios
ANDROID_OUT         ?= dist/android
TEST_OUT            ?= dist/test
IOS_NAME            ?= Gmrtd
AAR_NAME            ?= gmrtd.aar

# -------- Toolchain / Versions --------
MIN_IOS             ?= 13.0
MIN_ANDROID_SDK     ?= 24

# Namespacing for bindings
OBJC_PREFIX         ?= Gmrtd
ANDROID_JAVAPKG     ?= io.github.gmrtd

# Optional build tags for the mobile facade (leave blank if unused)
GO_TAGS             ?= mobile

# -------- Env --------
export GOPATH        ?= $(HOME)/go
export PATH          := $(GOPATH)/bin:$(PATH)
#export CGO_ENABLED   ?= 1
export IPHONEOS_DEPLOYMENT_TARGET ?= $(MIN_IOS)

# -------- Phonies --------
.PHONY: all clean tools lint-tools gomobile-init verify-env \
        ios android release checksums \
        test test-short test-race cover bench \
        fmt vet lint vuln tidy modverify gen ci

# =======================
# Top-level (build everything)
# =======================
all: tools gomobile-init ios android

clean:
	rm -rf dist build *.xcframework *.aar

# =======================
# Tools
# =======================
tools:
	@echo ">> Installing gomobile & gobind"
	go install golang.org/x/mobile/cmd/gomobile@latest
	go install golang.org/x/mobile/cmd/gobind@latest

# Optional: enhanced linters (staticcheck, govulncheck)
lint-tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

gomobile-init: verify-env
	@echo ">> gomobile init"
	gomobile init

verify-env:
	@which go >/dev/null || (echo "Go not found"; exit 1)

# =======================
# iOS binding
# =======================
ios: $(IOS_OUT)/$(IOS_NAME).xcframework
$(IOS_OUT)/$(IOS_NAME).xcframework:
	mkdir -p $(IOS_OUT)
	gomobile bind -v \
		-target=ios \
		-iosversion=$(MIN_IOS) \
		-o $(IOS_OUT)/$(IOS_NAME).xcframework \
		-prefix $(OBJC_PREFIX) \
		$(if $(GO_TAGS),-tags "$(GO_TAGS)",) \
		$(PKG_MOBILE)
	@echo ">> iOS XCFramework at $(IOS_OUT)/$(IOS_NAME).xcframework"

# =======================
# Android binding
# =======================
android: $(ANDROID_OUT)/$(AAR_NAME)
$(ANDROID_OUT)/$(AAR_NAME):
	mkdir -p $(ANDROID_OUT)
	ANDROID_HOME=$(ANDROID_HOME) ANDROID_NDK=$(ANDROID_NDK) \
	gomobile bind -v \
		-target=android/arm,android/arm64,android/amd64 \
		-androidapi=$(MIN_ANDROID_SDK) \
		-javapkg $(ANDROID_JAVAPKG) \
		-o $(ANDROID_OUT)/$(AAR_NAME) \
		$(if $(GO_TAGS),-tags "$(GO_TAGS)",) \
		$(PKG_MOBILE)
	@echo ">> Android AAR at $(ANDROID_OUT)/$(AAR_NAME)"

# =======================
# Releases / checksums
# =======================
checksums:
	mkdir -p dist
	cd dist && find . -type f \( -name '*.aar' -o -name '*.xcframework' -o -name '*.zip' -o -name 'coverage.*' \) -print0 | xargs -0 shasum -a 256 > checksums.txt
	@echo ">> checksums at dist/checksums.txt"

release: all
	cd $(IOS_OUT) && zip -qr $(IOS_NAME).xcframework.zip $(IOS_NAME).xcframework
	$(MAKE) checksums

# =======================
# Testing & Quality
# =======================

## Run all unit tests (excluding mobile binding by default)
test:
	@echo ">> go test (all pkgs)"
	mkdir -p $(TEST_OUT)
	go test -count=1 $(PKGS_NO_CMD)

## Fast tests: respect -short and skip longer cases
test-short:
	@echo ">> go test -short"
	mkdir -p $(TEST_OUT)
	go test -short -count=1 $(PKGS_NO_CMD)

## Race detector (quick suite)
test-race:
	@echo ">> go test -race -short"
	mkdir -p $(TEST_OUT)
	go test -race -short -count=1 $(PKGS_NO_CMD)

## Coverage (profile + HTML)
cover:
	@echo ">> coverage"
	mkdir -p $(TEST_OUT)
	go test -count=1 -covermode=atomic -coverprofile=$(TEST_OUT)/coverage.out $(PKGS_NO_CMD)
	go tool cover -html=$(TEST_OUT)/coverage.out -o $(TEST_OUT)/coverage.html
	@echo ">> coverage report: $(TEST_OUT)/coverage.html"

## Benchmarks
bench:
	@echo ">> benchmarks"
	go test -run=^$$ -bench=. -benchmem $(PKGS_NO_CMD)

## Formatting / vetting / lint
fmt:
	@echo ">> gofmt -l (fail if diffs)"
	@diff=$$(gofmt -l .); if [ -n "$$diff" ]; then echo "$$diff"; exit 1; fi

vet:
	@echo ">> go vet ./..."
	go vet ./...

lint: fmt vet
	@command -v staticcheck >/dev/null 2>&1 && { echo ">> staticcheck ./..."; staticcheck ./...; } || { echo ">> staticcheck not installed (run 'make lint-tools')"; }

vuln:
	@command -v govulncheck >/dev/null 2>&1 && { echo ">> govulncheck ./..."; govulncheck ./...; } || { echo ">> govulncheck not installed (run 'make lint-tools')"; }

## Module hygiene
tidy:
	go mod tidy

modverify:
	go mod verify

## Code generation (if you use go:generate)
gen:
	go generate ./...

# =======================
# CI convenience: quality gates then SDKs
# =======================
ci: tidy modverify lint test-race cover ios android
	@echo ">> CI pipeline done"