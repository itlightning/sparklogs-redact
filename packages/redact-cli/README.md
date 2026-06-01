# @sparklogs/redact-cli

The **Node CLI** for [sparklogs-redact](../../README.md). The only Node-specific package
(`fs`/`process`/`stdin`); it wraps the isomorphic [`@sparklogs/redact-core`](../redact-core) and
bundles it into a self-contained `dist/cli.js` (no runtime `node_modules` resolution needed).

The executable is named **`sparklogs-redact`**.

## Build + run

```bash
# from the repo root
npm install
npm run build                      # builds core, then this cli -> dist/cli.js

node packages/redact-cli/dist/cli.js scan ./fixtures
```

During development you can also run the TypeScript entry directly (Node ≥ 23 strips the types), as
long as the workspace is linked (`npm install`) and the core has been built:

```bash
node packages/redact-cli/src/cli.ts profiles
```

## Commands

```bash
# Redact a file to stdout
sparklogs-redact redact /path/to/app.log

# Redact stdin -> a file, with a per-category summary on stderr
cat app.log | sparklogs-redact redact - -o app.redacted.log --stats

# Redact several files from one dataset through ONE shared correlation map (same real token ->
# same pseudonym in every file); persist/seed the map to top up the same dataset later.
sparklogs-redact redact a.log b.log --out-dir /tmp/clean --save-map /tmp/d.redact-map.json
sparklogs-redact redact c.log       --out-dir /tmp/clean --load-map /tmp/d.redact-map.json

# Scan a tree for residual (un-redacted) PII — exit 1 if any is found (CI gate)
sparklogs-redact scan ./fixtures

# List built-in profiles
sparklogs-redact profiles
```

The `*.redact-map.json` correlation map embeds RAW original tokens (i.e. RAW PII) — it is gitignored
and **must never be committed**.

### Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `redact` | ok | — | usage / IO error |
| `scan` | clean | residual PII found | usage / IO error |

## License

[MIT](../../LICENSE)
