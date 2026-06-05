# sparklogs-redact

Tooling to detect and consistently **pseudonymise** PII in log text, with a **residual-PII scanner**
you can wire into CI as a gate. Built for Windows-style sys/app logs first,
but the detection rules are portable JSON specs you can extend for any log format.

This is an **npm-workspaces monorepo**. The pieces are split along package boundaries so the
isomorphic core stays dependency-free and browser-safe, while the Node CLI and React UI build on top
of it:

| Package | Path | What it is |
|---|---|---|
| [`@sparklogs/redact-core`](packages/redact-core) | `packages/redact-core` | **Isomorphic** detection + consistent-mapping engine + scanner. Pure string/regex; safe in Node or the browser. Zero runtime deps. Driven by portable JSON detection specs. |
| [`@sparklogs/redact-cli`](packages/redact-cli) | `packages/redact-cli` | **Node CLI** (`sparklogs-redact`): redact files / scan a tree for residual PII (CI gate). Bundles the core into a self-contained `dist/cli.js`. |
| [`@sparklogs/redact-react`](packages/redact-react) | `packages/redact-react` | **React components** for in-browser local redaction — redact client-side, then upload. Builds on the isomorphic core (no server ever sees raw PII). |

## Why a monorepo

The core, CLI, and UI evolve together (new detectors, profile changes, mapping behaviour) and share
one set of detection specs, so versioning and testing them in lockstep is the point. The split keeps
the **core strictly isomorphic and zero-dependency** — only the CLI imports Node built-ins, and only
the React package pulls in a UI toolchain — so a browser bundle of the core never drags in `fs` or a
build-time dependency tree. The core being client-safe is exactly what makes in-browser local
redaction (the React package) possible.

## Versioning

All publishable packages (`@sparklogs/redact-core`, `@sparklogs/redact-cli`, `@sparklogs/redact-react`)
share **one semver** — bump every `packages/*/package.json` together on release, even when only one
package changed functionally.

- **Minor** (`0.1.0` → `0.2.0`): backward-compatible API or notable features.
- **Patch**: bug fixes, no public API change.
- **Major** (or pre-1.0 minor when breaking): incompatible API changes.

Each package has a `CHANGELOG.md`. During development, edit **`## Unreleased`** in the package(s) you
changed; either **all three** changelogs have that section or **none** do (release PR). On release,
move `## Unreleased` → `## X.Y.Z` in every changelog (packages with no functional change get a
lockstep stub line), set all `package.json` versions to `X.Y.Z`, and set `@sparklogs/redact-core` in
cli/react to `^X.Y.Z`.

CI runs `make check-versions` (`scripts/check-lockstep-versions.mjs`) to enforce lockstep versions,
core dependency ranges, and changelog symmetry.

**Agents:** never bump a single package version; run `make check-versions` after version or changelog
edits.

## Develop

```bash
npm install              # link workspaces + install dev tooling (tsup, typescript)
npm run build            # build core, cli, react -> packages/*/dist
npm test                 # run each package's test suite (node --test)
npm run typecheck        # tsc --noEmit in core, cli, and react
```

For a reproducible tree (same as CI), use `npm ci` instead of `npm install` when
`package-lock.json` is present.

## CI

GitHub Actions runs the same gate as local dev:

```bash
make ci    # npm ci · build · typecheck · test · audit · smoke · check-versions
```

`make ci` installs **all** workspaces (including React devDependencies), builds every package,
typechecks core/cli/react, runs all package tests, runs `npm audit` (logs all findings; **fails** on
high/critical in **production** deps only), smoke-tests the CLI bundle, and verifies lockstep package
versions plus changelog conventions (`make check-versions`).

On pull requests, the workflow posts a sticky summary comment (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Synthetic clean fixtures for `scan` live
under [`test/fixtures/clean/`](test/fixtures/clean/) (`*.fixture` synthetic logs; never commit raw
customer `*.log` files — see that directory's README).

### CLI-only in another repo (e.g. source-library PII scan)

When you only need the self-contained CLI bundle and want to avoid pulling the full monorepo gate,
install the core + CLI workspaces **and** root dev tooling (`tsup` lives at the repo root; npm 11+
does not install it with a bare `-w` filter):

```bash
npm install -w @sparklogs/redact-core -w @sparklogs/redact-cli --include-workspace-root
npm run build -w @sparklogs/redact-core
npm run build -w @sparklogs/redact-cli
node packages/redact-cli/dist/cli.js scan ./some/dir
```

Alternatively, run `npm ci` once and build only the workspaces you need; React deps are installed
but unused.

## Quick start (CLI)

After `npm run build`, the CLI lives at `packages/redact-cli/dist/cli.js`:

```bash
node packages/redact-cli/dist/cli.js redact /path/to/app.log -o app.redacted.log --stats
node packages/redact-cli/dist/cli.js scan  ./fixtures        # exit 1 if any residual PII
node packages/redact-cli/dist/cli.js profiles
```

Full command reference: [`packages/redact-cli/README.md`](packages/redact-cli/README.md). Library
API + detection-profile docs: [`packages/redact-core/README.md`](packages/redact-core/README.md).
React wizard: [`packages/redact-react/README.md`](packages/redact-react/README.md).

## Limitations

- **Pseudonymization, not anonymization** — consistent fakes preserve structure and correlations; a clean `scan` does not mean safe to publish without review.
- **Regex-based** — false negatives/positives depend on profile and log shape; built-in profiles deliberately skip some shapes (e.g. `windows-log` and IPv4).
- Not legal/compliance advice.

Package-specific caveats:
- [`redact-core`](packages/redact-core/README.md#limitations)
- [`redact-cli`](packages/redact-cli/README.md#limitations)
- [`redact-react`](packages/redact-react/README.md#limitations)

## License

[MIT](LICENSE)
