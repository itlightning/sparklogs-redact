# sparklogs-redact

Tooling to detect and consistently **pseudonymise** PII in log text, with a **residual-PII scanner**
you can wire into CI as a gate. Built for Windows-style sys/app logs first,
but the detection rules are portable JSON specs you can extend for any log format.

This is an **npm-workspaces monorepo**. The pieces are split along package boundaries so the
isomorphic core stays dependency-free and browser-safe, while the Node CLI and (forthcoming) React
UI build on top of it:

| Package | Path | What it is |
|---|---|---|
| [`@sparklogs/redact-core`](packages/redact-core) | `packages/redact-core` | **Isomorphic** detection + consistent-mapping engine + scanner. Pure string/regex; safe in Node or the browser. Zero runtime deps. Driven by portable JSON detection specs. |
| [`@sparklogs/redact-cli`](packages/redact-cli) | `packages/redact-cli` | **Node CLI** (`sparklogs-redact`): redact files / scan a tree for residual PII (CI gate). Bundles the core into a self-contained `dist/cli.js`. |
| `@sparklogs/redact-react` | `packages/redact-react` *(planned)* | **React components** for in-browser local redaction — redact client-side, then upload. Builds on the isomorphic core (no server ever sees raw PII). |

## Why a monorepo

The core, CLI, and UI evolve together (new detectors, profile changes, mapping behaviour) and share
one set of detection specs, so versioning and testing them in lockstep is the point. The split keeps
the **core strictly isomorphic and zero-dependency** — only the CLI imports Node built-ins, and only
the React package pulls in a UI toolchain — so a browser bundle of the core never drags in `fs` or a
build-time dependency tree. The core being client-safe is exactly what makes in-browser local
redaction (the React package) possible.

## Develop

```bash
npm install              # link workspaces + install dev tooling (tsup, typescript)
npm run build            # build core, then cli (the cli bundles the core's dist) -> packages/*/dist
npm test                 # run each package's test suite (node --test)
```

Build only the core + CLI (e.g. for the source-library PII-scan gate, skipping the React toolchain):

```bash
npm install  -w @sparklogs/redact-core -w @sparklogs/redact-cli
npm run build -w @sparklogs/redact-core
npm run build -w @sparklogs/redact-cli
node packages/redact-cli/dist/cli.js scan ./some/dir
```

> Adding `@sparklogs/redact-react` later: drop it under `packages/`, then extend the root `build`
> script to build it after the core (`&& npm run build -w @sparklogs/redact-react`). Scoped installs
> like the one above never pull its React deps.

## Quick start (CLI)

After `npm run build`, the CLI lives at `packages/redact-cli/dist/cli.js`:

```bash
node packages/redact-cli/dist/cli.js redact /path/to/app.log -o app.redacted.log --stats
node packages/redact-cli/dist/cli.js scan  ./fixtures        # exit 1 if any residual PII
node packages/redact-cli/dist/cli.js profiles
```

Full command reference: [`packages/redact-cli/README.md`](packages/redact-cli/README.md). Library
API + detection-profile docs: [`packages/redact-core/README.md`](packages/redact-core/README.md).

## License

[MIT](LICENSE)
