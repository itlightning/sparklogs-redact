# sparklogs-redact — local CI entrypoint (mirrors .github/workflows/ci.yml)
NPM ?= npm
NODE ?= node
CLI := packages/redact-cli/dist/cli.js
CLEAN_FIXTURE := test/fixtures/clean/sample.log

.PHONY: ci install build typecheck test smoke help

ci: install build typecheck test smoke
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

smoke:
	@echo "== smoke: CLI profiles =="
	$(NODE) $(CLI) profiles
	@echo "== smoke: scan clean fixtures =="
	$(NODE) $(CLI) scan $(CLEAN_FIXTURE) --quiet
	@echo "== smoke OK =="

help:
	@echo ""
	@echo "sparklogs-redact — make targets"
	@echo "  make ci         npm ci + build + typecheck + test + smoke (full gate)"
	@echo "  make install    npm ci (all workspaces)"
	@echo "  make build      npm run build (core, cli, react)"
	@echo "  make typecheck  tsc --noEmit in core, cli, and react"
	@echo "  make test       node --test in every package that defines test"
	@echo "  make smoke      CLI profiles + scan on test/fixtures/clean/sample.log"
	@echo ""
