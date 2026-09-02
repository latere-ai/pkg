# SPDX-FileCopyrightText: 2026 Latere AI
# SPDX-License-Identifier: Apache-2.0

.PHONY: check test test-race race fuzz cover cover-html fmt fmt-check hooks vuln lint-modernize lint-config lint \
	test-hermetic cgo-free deps validate no-tracked-specs release release-notes

GO ?= go
FUZZTIME ?= 30s

test:
	@go tool lateregate test

# race is the gate's name; test-race stays as an alias.
test-race race:
	@go tool lateregate race

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

# govulncheck at the version lateregate pins, over every package. The
# reachability it reports is a call path, not a module in the graph.
vuln:
	@go tool lateregate vuln

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

# .golangci.yml is generated and gitignored: golangci-lint cannot inherit a
# shared config, so it is rendered from latere.ai/x/ci-gate on every run.
# Regenerating rather than committing is what makes divergence impossible
# instead of merely detectable.
lint-config:
	@$(GO) tool lateregate golangci

# golangci-lint at the version lateregate pins, against the config it renders.
lint:
	@go tool lateregate lint

# hooks installs the repository git hooks; the pre-commit delegates to lateregate.
hooks:
	git config core.hooksPath .githooks
	@[ -e CLAUDE.md ] || [ -L CLAUDE.md ] || ln -s AGENTS.md CLAUDE.md
	@echo "installed git hooks (core.hooksPath=.githooks)"

# release cuts a tag from CHANGELOG.md: the notes under "Unreleased" become
# the section for VERSION, then commit, tag, and push. The release workflow
# publishes the GitHub release from that section. See .github/scripts.
release:
	@.github/scripts/release-cut.sh "$(VERSION)"

# release-notes prints the changelog section for TAG, or fails.
release-notes:
	@.github/scripts/release-notes.sh "$(TAG)"

# The whole shared bar. Every gate lives in lateregate, pinned as a tool in
# go.mod; this target is a name for `go tool lateregate` and nothing else.
# The plan: `go tool lateregate list`. One gate: `go tool lateregate <gate>`.
check:
	@go tool lateregate
