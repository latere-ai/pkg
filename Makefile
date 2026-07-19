.PHONY: test race fuzz cover cover-html fmt fmt-check hooks

test:
	go test -v -count=1 ./...

race:
	go test -v -race -count=1 ./...

fuzz:
	go test -fuzz=FuzzSetup -fuzztime=30s ./otel/
	go test -fuzz=FuzzStripScheme -fuzztime=30s ./otel/
	go test -fuzz=FuzzVersion -fuzztime=30s ./otel/
	go test -fuzz=FuzzRouteFromPattern -fuzztime=30s ./otel/
	go test -fuzz=FuzzValidate -fuzztime=30s ./jwtauth/
	go test -fuzz=FuzzParseJWKS -fuzztime=30s ./jwtauth/
	go test -fuzz=FuzzReader -fuzztime=30s ./llmdialect/internal/sse/
	go test -fuzz=FuzzDecodeRequest -fuzztime=30s ./llmdialect/anthropic/
	go test -fuzz=FuzzBackendDecodeResponse -fuzztime=30s ./llmdialect/anthropic/
	go test -fuzz=FuzzDecodeResponse -fuzztime=30s ./llmdialect/openaichat/
	go test -fuzz=FuzzEventDecoder -fuzztime=30s ./llmdialect/openaichat/
	go test -fuzz=FuzzFrontendDecodeRequest -fuzztime=30s ./llmdialect/openaichat/
	go test -fuzz=FuzzDecodeRequest -fuzztime=30s ./llmdialect/openairesp/

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
