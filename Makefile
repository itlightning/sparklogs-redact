# sparklogs-redact — local CI entrypoint (mirrors .github/workflows/ci.yml)
NPM ?= npm
NODE ?= node
CLI := packages/redact-cli/dist/cli.js
CLEAN_FIXTURE := test/fixtures/clean/sample.fixture

.PHONY: ci install build typecheck test audit smoke help

ci: install build typecheck test audit smoke
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
	@echo "== test (all workspaces with a test script) =="
	$(NPM) test

# Log all findings (incl. dev); fail only on high/critical in production dependencies.
audit:
	@echo "== audit: full report (all deps; informational) =="
	-$(NPM) audit || true
	@echo "== audit: gate (production deps, high and critical) =="
	$(NPM) audit --omit=dev --audit-level=high

smoke:
	@echo "== smoke: CLI profiles =="
	$(NODE) $(CLI) profiles
	@echo "== smoke: scan clean fixtures =="
	$(NODE) $(CLI) scan $(CLEAN_FIXTURE) --quiet
	@echo "== smoke OK =="

help:
	@echo ""
	@echo "sparklogs-redact — make targets"
	@echo "  make ci         npm ci + build + typecheck + test + audit + smoke (full gate)"
	@echo "  make install    npm ci (all workspaces)"
	@echo "  make build      npm run build (core, cli, react)"
	@echo "  make typecheck  tsc --noEmit in core, cli, and react"
	@echo "  make test       node --test in every package that defines test"
	@echo "  make audit      npm audit (log all); fail on prod high/critical"
	@echo "  make smoke      CLI profiles + scan on test/fixtures/clean/sample.fixture"
	@echo ""
