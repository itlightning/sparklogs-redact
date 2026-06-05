# @sparklogs/redact-core

The **isomorphic core** of [sparklogs-redact](../../README.md): detect and consistently
**pseudonymise** PII in log text, with a **residual-PII scanner**. Pure string/regex work (only
`Uint8Array` + `TextDecoder`), so it's safe to import in **Node or the browser** and has **zero
runtime dependencies**.

- **Consistent mapping** — the same token always maps to the same fake within a pass, so log
  structure and correlations survive redaction. The lookup table is discarded after each pass
  (keyless determinism: no persisted map that could re-identify anyone).
- **Format-shaped fakes** — replacements live in reserved spaces (RFC 1918 / TEST-NET IPs,
  RFC 7042 doc MACs, `example.invalid` emails, `\Users\User00001`), so redacted text still parses.
- **Idempotent + gate-friendly** — each detector declares a `safe` shape describing a token that has
  *already* been redacted. Re-redacting is a no-op, and the scanner reports only un-redacted, real
  PII (placeholders read as clean).

## Library use

```ts
import { Redactor, loadProfile, decode } from "@sparklogs/redact-core";

const redactor = new Redactor(loadProfile("windows-log"));

const result = redactor.redact("C:\\Users\\alice\\AppData\\... S-1-5-21-111-222-333-1001");
result.text;        // "...\\Users\\User00001\\... S-1-5-21-0-0-0-1001"
result.stats;       // { username: 1, sid: 1 }
result.mappingSize; // 2

// Residual-PII gate: [] on properly redacted text; reported samples are MASKED, never raw.
redactor.scan(result.text); // []
```

### Redaction metadata (for before/after UIs)

`result.redactions` holds one `RedactionRecord` per replaced token, in document order, carrying **no
raw PII** (only a shape-preserving `masked` sample) — safe to keep or transmit alongside the output.
Each record locates the token on **both** sides of the redaction:

- `start` / `end` — 0-based offsets of the original token in the **input** text.
- `outStart` / `outEnd` — 0-based offsets of the fake in `result.text` (the **output**).

So a browser preview can highlight the redacted side directly — the format-shaped fakes are realistic
and not regex-recoverable, so the output offsets are the reliable way to find them:

```ts
for (const rec of result.redactions) {
  input.slice(rec.start, rec.end);          // the original token (raw — only available if you hold the source)
  result.text.slice(rec.outStart, rec.outEnd); // === rec.replacement, the fake in the output
  rec.category;                              // e.g. "username", "email", "ipv4"
}
```

## Detection profiles

Profiles are portable JSON specs under [`patterns/`](patterns/). Each detector's **full regex match
is the sensitive token** — locating context (e.g. a `\Users\` prefix) is excluded with look-around,
so the engine replaces `match[0]` directly with no capture-group bookkeeping.

The built-in **`windows-log`** profile covers usernames in `\Users\` paths, user SIDs
(`S-1-5-21-…`), emails, UNC hostnames, and MAC addresses. It deliberately **does not** redact IPv4
(in CBS/DISM the dotted-quad shape is almost always a Windows *version* string like `10.0.0.0`) or
Microsoft WinSxS assembly names (public component identifiers, load-bearing for corruption
analysis). See the `notes` array in [`patterns/windows-log.json`](patterns/windows-log.json).

Add a profile by dropping a JSON file in `patterns/` and registering it in
[`src/detectors.ts`](src/detectors.ts).

## Development

```bash
node --test          # run the test suite (Node built-in runner, TS via type-stripping)
npm run build        # bundle to dist/ via tsup (for publishing / consumption by redact-cli)
```

## Limitations

- Regex detectors may miss unanticipated PII and can false-positive (especially `generic` / `secret`).
- Profile `notes` document intentional skips (e.g. `windows-log` does not redact dotted-quad “version” strings).
- **Pseudonymization** keeps cross-token correlations within a pass; that can aid analysis but is not full anonymization.
- `scan() === []` is a useful gate, not a guarantee of publishable output.
- Custom profiles: pass `Detector[]` to `new Redactor(...)` or import JSON from `patterns/`; `loadProfile()` only knows built-ins.
- `MappingEngine.toJSON()` / CLI `--save-map` files hold **raw originals** — treat like secrets; never commit.

## License

[MIT](../../LICENSE)
