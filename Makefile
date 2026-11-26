# sparklogs-redact — local CI entrypoint (mirrors .github/workflows/ci.yml)
NPM ?= npm
NODE ?= node
CLI := packages/redact-cli/dist/cli.js
CLEAN_FIXTURE := test/fixtures/clean/sample.fixture

.PHONY: ci install build typecheck test audit smoke check-versions help

ci: install build typecheck test audit smoke check-versions
	@echo "== sparklogs-redact CI OK =="

install:
	@echo "== install (all workspaces, lockfile-pinned) =="
	$(NPM) ci

build:
	@echo "== build (core, cli, react) =="
	$(NPM) run build

typecheck:
	@echo "== typecheck (core + cli + react) =="
	$(NPM) run typecheck

test:
	@echo "== test (repo scripts + all workspaces with a test script) =="
	$(NPM) test

# Fails on any advisory in any dependency of any tracked lockfile (shipped or development, any
# severity) that has no reviewed entry in advisory-ignore.json, and on any dependency from outside
# the npm registry that advisory-sources.json does not declare.
audit:
	@echo "== audit (all deps, any severity; ignore entries in advisory-ignore.json) =="
	$(NODE) scripts/audit-gate.mjs

smoke:
	@echo "== smoke: CLI profiles =="
	$(NODE) $(CLI) profiles
	@echo "== smoke: scan clean fixtures =="
	$(NODE) $(CLI) scan $(CLEAN_FIXTURE) --quiet
	@echo "== smoke OK =="

check-versions:
	@echo "== check-versions (lockstep semver + changelogs) =="
	$(NODE) scripts/check-lockstep-versions.mjs

help:
	@echo ""
	@echo "sparklogs-redact — make targets"
	@echo "  make ci         npm ci + build + typecheck + test + audit + smoke + check-versions"
	@echo "  make install    npm ci (all workspaces)"
	@echo "  make build      npm run build (core, cli, react)"
	@echo "  make typecheck  tsc --noEmit in core, cli, and react"
	@echo "  make test       repo script tests + every package that defines test"
	@echo "  make audit      fail on any advisory without an advisory-ignore.json entry"
	@echo "  make smoke      CLI profiles + scan on test/fixtures/clean/sample.fixture"
	@echo "  make check-versions  lockstep package.json + CHANGELOG gate"
	@echo ""
