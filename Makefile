.PHONY: test test-race race fuzz cover cover-html fmt fmt-check hooks vuln lint-modernize lint-config \
	test-hermetic cgo-free deps validate no-tracked-specs

GO ?= go
FUZZTIME ?= 30s

test:
	$(GO) vet ./...
	$(GO) test -count=1 ./...

# test-race is the contract's name; race stays as an alias.
test-race race:
	$(GO) test -race -count=1 ./...

# The suite with only the Go toolchain on PATH. A test that depends on what
# happens to be installed passes locally and fails on a runner, which is the
# worst order to find out.
test-hermetic:
	@$(GO) tool lateregate hermetic

fuzz:
	@set -eu; \
	for pkg in $$($(GO) list ./...); do \
		targets=$$($(GO) test -list '^Fuzz' "$$pkg" | awk '/^Fuzz/ {print $$1}'); \
		for target in $$targets; do \
			echo "fuzz $$pkg/$$target"; \
			$(GO) test -run='^$$' -fuzz="^$${target}$$" -fuzztime="$(FUZZTIME)" "$$pkg"; \
		done; \
	done

# Per package rather than as a repository average. The average passed at 95%
# while pgxmigrate sat at 82.1%: one package below the line and 47 above it
# carrying the number. The floor and any exemptions live in .lateregate.yaml.
cover:
	$(GO) test -coverprofile=coverage.out -covermode=atomic -coverpkg=./... ./...
	@$(GO) tool lateregate cover -profile=coverage.out

cover-html: cover
	go tool cover -html=coverage.out

# vuln fails when this module imports or calls vulnerable code.
#
# govulncheck reports at three depths, distinguished in the JSON by how much
# of the first trace frame is filled in: a called symbol (function set), an
# imported package (package set), and a required module (module only). The
# first two are what this module exposes to its consumers -- a called symbol
# is reachable outright, and an imported vulnerable package is one call away
# and is how GO-2026-5158, the otel baggage DoS, presented. Findings against
# modules we merely require are left to show in the report without failing a
# build that introduced them nowhere.
#
# govulncheck exits 0 whether or not it finds anything, so the result has to
# be read rather than inferred from the status. That cuts both ways: every
# step below is checked, because a security gate that goes green when the
# scanner never ran is worse than no gate at all.
vuln:
	@command -v jq >/dev/null 2>&1 || { echo "FAIL: vuln needs jq to read the report"; exit 1; }
	@command -v govulncheck >/dev/null 2>&1 || $(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	@bin=$$(command -v govulncheck 2>/dev/null); \
	if [ -z "$$bin" ]; then \
		gobin=$$($(GO) env GOBIN); [ -n "$$gobin" ] || gobin="$$($(GO) env GOPATH)/bin"; \
		bin="$$gobin/govulncheck"; \
	fi; \
	[ -x "$$bin" ] || { echo "FAIL: govulncheck is not on PATH and was not found after install"; exit 1; }; \
	report=$$(mktemp); trap 'rm -f "$$report"' EXIT; \
	"$$bin" -format json ./... > "$$report" || { echo "FAIL: govulncheck did not complete; the scan proves nothing"; exit 1; }; \
	[ -s "$$report" ] || { echo "FAIL: govulncheck wrote an empty report"; exit 1; }; \
	raw=$$(jq -r 'select(.finding) | select(.finding.trace[0].package != null) | .finding.osv' "$$report") || { echo "FAIL: could not parse the govulncheck report"; exit 1; }; \
	found=$$(printf '%s\n' "$$raw" | sed '/^$$/d' | sort -u); \
	if [ -n "$$found" ]; then \
		echo "FAIL: vulnerabilities in code this module imports or calls:"; \
		echo "$$found" | sed 's|^|  https://pkg.go.dev/vuln/|'; \
		echo "run 'govulncheck ./...' for the call traces"; \
		exit 1; \
	fi; \
	echo "no vulnerabilities in imported or called code"

# fmt formats all Go sources in place.
fmt:
	gofmt -w .

# fmt-check fails if any Go source is not gofmt-formatted.
# The three gates that defend a promise this module makes. Run as one job;
# each keeps its own target name, so a failure says which promise broke.
validate: no-tracked-specs deps cgo-free vuln fuzz

# This module is public and carries client primitives only. Internal planning
# docs live in a private repository, never here.
no-tracked-specs:
	@tracked=$$(git ls-files specs/); \
	if [ -n "$$tracked" ]; then \
		echo "internal specs/ files are tracked in this public module:"; \
		echo "$$tracked"; \
		exit 1; \
	fi; \
	echo "no internal specs tracked"

# llmdialect is stdlib-only, and tgo's own footprint gate watches this subtree
# from the outside. Watching it from there catches the breakage; watching it
# here is where it can be prevented.
deps:
	@$(GO) tool lateregate depcheck

# This module is pure Go, and 16 repositories inherit whatever it reaches.
# Reads source rather than the build: a file can import "C" behind a build tag
# this platform does not select and still be a violation.
cgo-free:
	@$(GO) tool lateregate cgo-free

fmt-check:
	@$(GO) tool lateregate fmt-check

# lint-modernize fails on code that a standard library call already covers.
# The disabled fixers are named in .lateregate.yaml, and lateregate checks each
# still exists, because `go fix` rejects an unknown -name=false and the gate
# would then pass silently.
# It runs the toolchain modernizers, which overlap golangci-lint's modernize
# linter but add three it does not carry: buildtag, hostport, and the
# go:fix inline directives. newexpr and errorsastype are off for the reasons
# recorded in .golangci.yml.
# Only a non-empty patch fails the target. go fix also exits non-zero when a
# package does not type-check, which is a build error rather than a finding,
# so stderr is dropped and the decision rests on the patch alone.
lint-modernize:
	@$(GO) tool lateregate modernize

# .golangci.yml is generated: golangci-lint cannot inherit a shared config, so
# it is rendered from latere.ai/x/ci-gate and checked here. Regenerate with
# `go tool lateregate golangci -write`.
lint-config:
	@$(GO) tool lateregate golangci

# hooks installs the repository git hooks (pre-commit gofmt guard).
hooks:
	git config core.hooksPath .githooks
	@echo "installed git hooks (core.hooksPath=.githooks)"
