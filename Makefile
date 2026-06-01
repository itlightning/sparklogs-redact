# sparklogs-redact — local CI entrypoint (mirrors .github/workflows/ci.yml)
NPM ?= npm
NODE ?= node
CLI := packages/redact-cli/dist/cli.js
CLEAN_FIXTURE := test/fixtures/clean/sample.log

.PHONY: ci install build typecheck test smoke help

ci: install build typecheck test smoke
	@echo "== sparklogs-redact CI OK =="

install:
	@echo "== install (core + cli workspaces) =="
	$(NPM) install -w @sparklogs/redact-core -w @sparklogs/redact-cli

build:
	@echo "== build @sparklogs/redact-core =="
	$(NPM) run build -w @sparklogs/redact-core
	@echo "== build @sparklogs/redact-cli =="
	$(NPM) run build -w @sparklogs/redact-cli

typecheck:
	@echo "== typecheck (tsc --noEmit, core + cli src + test) =="
	$(NPM) run typecheck

test:
	@echo "== test @sparklogs/redact-core =="
	$(NPM) test -w @sparklogs/redact-core
	@echo "== test @sparklogs/redact-cli =="
	$(NPM) test -w @sparklogs/redact-cli

smoke:
	@echo "== smoke: CLI profiles =="
	$(NODE) $(CLI) profiles
	@echo "== smoke: scan clean fixtures =="
	$(NODE) $(CLI) scan $(CLEAN_FIXTURE) --quiet
	@echo "== smoke OK =="

help:
	@echo ""
	@echo "sparklogs-redact — make targets"
	@echo "  make ci       install + build + typecheck + test + smoke (full gate)"
	@echo "  make typecheck  tsc --noEmit (core + cli, src + test)"
	@echo "  make install  npm install (core + cli workspaces only)"
	@echo "  make build    tsup both packages"
	@echo "  make test     node --test in core and cli"
	@echo "  make smoke    CLI profiles + scan on test/fixtures/clean/sample.log"
	@echo ""
