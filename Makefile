.PHONY: test race fuzz cover cover-html fmt fmt-check hooks

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

# fmt formats all Go sources in place.
fmt:
	gofmt -w .

# fmt-check fails if any Go source is not gofmt-formatted.
fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt: unformatted files:"; echo "$$out"; exit 1; fi

# hooks installs the repository git hooks (pre-commit gofmt guard).
hooks:
	git config core.hooksPath .githooks
	@echo "installed git hooks (core.hooksPath=.githooks)"
