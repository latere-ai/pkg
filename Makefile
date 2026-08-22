.PHONY: test race fuzz cover cover-html fmt fmt-check hooks vuln lint-modernize

GO ?= go
FUZZTIME ?= 30s

test:
	go test -v -count=1 ./...

race:
	go test -v -race -count=1 ./...

fuzz:
	@set -eu; \
	for pkg in $$($(GO) list ./...); do \
		targets=$$($(GO) test -list '^Fuzz' "$$pkg" | awk '/^Fuzz/ {print $$1}'); \
		for target in $$targets; do \
			echo "fuzz $$pkg/$$target"; \
			$(GO) test -run='^$$' -fuzz="^$${target}$$" -fuzztime="$(FUZZTIME)" "$$pkg"; \
		done; \
	done

cover:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out
	@COVERAGE=$$(go tool cover -func=coverage.out | grep total | awk '{print substr($$3, 1, length($$3)-1)}'); \
	echo "Total coverage: $${COVERAGE}%"; \
	if [ $$(echo "$${COVERAGE} < 95" | bc -l) -eq 1 ]; then \
		echo "FAIL: coverage $${COVERAGE}% is below 95% threshold"; \
		exit 1; \
	fi

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
fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt: unformatted files:"; echo "$$out"; exit 1; fi

# lint-modernize fails on code that a standard library call already covers.
# It runs the toolchain modernizers, which overlap golangci-lint's modernize
# linter but add three it does not carry: buildtag, hostport, and the
# go:fix inline directives. newexpr and errorsastype are off for the reasons
# recorded in .golangci.yml.
# Only a non-empty patch fails the target. go fix also exits non-zero when a
# package does not type-check, which is a build error rather than a finding,
# so stderr is dropped and the decision rests on the patch alone.
lint-modernize:
	@for fixer in newexpr errorsastype; do \
		$(GO) tool fix help 2>&1 | grep -q "^    $$fixer " || { \
			echo "go fix no longer carries the $$fixer fixer, so -$$fixer=false is rejected and this check passes silently"; \
			exit 1; \
		}; \
	done
	@patch=$$($(GO) fix -diff -newexpr=false -errorsastype=false ./... 2>/dev/null); \
	if [ -n "$$patch" ]; then \
		echo "$$patch"; \
		echo "go fix: the diff above is already in the standard library; apply it with go fix"; \
		exit 1; \
	fi

# hooks installs the repository git hooks (pre-commit gofmt guard).
hooks:
	git config core.hooksPath .githooks
	@echo "installed git hooks (core.hooksPath=.githooks)"
