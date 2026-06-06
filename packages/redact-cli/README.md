# @sparklogs/redact-cli

Node CLI for [`@sparklogs/redact-core`](https://www.npmjs.com/package/@sparklogs/redact-core):
**redact** log files with consistent pseudonyms, or **scan** a tree for residual (un-redacted) PII as
a CI gate. Self-contained bundle; no runtime `node_modules` resolution.

The executable is **`sparklogs-redact`**.

From the [sparklogs-redact](https://github.com/itlightning/sparklogs-redact) monorepo. Wraps
[`@sparklogs/redact-core`](https://www.npmjs.com/package/@sparklogs/redact-core) at the same version.
For in-browser upload flows, see
[`@sparklogs/redact-react`](https://www.npmjs.com/package/@sparklogs/redact-react).

## Install

```bash
npm install @sparklogs/redact-cli
```

Then run via `npx` or add `node_modules/.bin` to your PATH:

```bash
npx sparklogs-redact --help
```

Global install also works: `npm install -g @sparklogs/redact-cli`.

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

# Scan a tree for residual (un-redacted) PII; exit 1 if any is found (CI gate)
sparklogs-redact scan ./fixtures

# List built-in profiles
sparklogs-redact profiles
```

The `*.redact-map.json` correlation map embeds RAW original tokens (i.e. RAW PII). Treat as secret
material and **never commit** it.

### Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `redact` | ok | n/a | usage / IO error |
| `scan` | clean | residual PII found | usage / IO error |

## Limitations

- `scan` only catches patterns the selected profile(s) know; a pass is not "no PII anywhere."
- Same engine limits as [`@sparklogs/redact-core`](https://www.npmjs.com/package/@sparklogs/redact-core#limitations).
- `--save-map` / `--load-map` correlation files embed **raw tokens**; secret material, never commit.

## License

[MIT](https://github.com/itlightning/sparklogs-redact/blob/main/LICENSE)
