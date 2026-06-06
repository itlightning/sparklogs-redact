# @sparklogs/redact-core

Detect and consistently **pseudonymise** PII in log text, with a **residual-PII scanner**. Pure
string/regex work (only `Uint8Array` + `TextDecoder`), safe to import in **Node or the browser** with
**zero runtime dependencies**.

- **Consistent mapping**: the same token always maps to the same fake within a pass, so log
  structure and correlations survive redaction. The lookup table is discarded after each pass
  (keyless determinism: no persisted map that could re-identify anyone).
- **Format-shaped fakes**: replacements live in reserved spaces (RFC 1918 / TEST-NET IPs,
  RFC 7042 doc MACs, `example.invalid` emails, `\Users\User00001`), so redacted text still parses.
- **Idempotent + gate-friendly**: each detector declares a `safe` shape describing a token that has
  *already* been redacted. Re-redacting is a no-op, and the scanner reports only un-redacted, real
  PII (placeholders read as clean).

From the [sparklogs-redact](https://github.com/itlightning/sparklogs-redact) monorepo. Published at
the same version as [`@sparklogs/redact-cli`](https://www.npmjs.com/package/@sparklogs/redact-cli)
and [`@sparklogs/redact-react`](https://www.npmjs.com/package/@sparklogs/redact-react).

## Install

```bash
npm install @sparklogs/redact-core
```

## Use

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
raw PII** (only a shape-preserving `masked` sample), safe to keep or transmit alongside the output.
Each record locates the token on **both** sides of the redaction:

- `start` / `end`: 0-based offsets of the original token in the **input** text.
- `outStart` / `outEnd`: 0-based offsets of the fake in `result.text` (the **output**).

So a browser preview can highlight the redacted side directly; the format-shaped fakes are realistic
and not regex-recoverable, so the output offsets are the reliable way to find them:

```ts
for (const rec of result.redactions) {
  input.slice(rec.start, rec.end);          // the original token (raw; only if you hold the source)
  result.text.slice(rec.outStart, rec.outEnd); // === rec.replacement, the fake in the output
  rec.category;                              // e.g. "username", "email", "ipv4"
}
```

## Detection profiles

Profiles are portable JSON specs. Built-in profiles: **`windows-log`**, **`generic`**, **`secret`**.

The **`windows-log`** profile covers usernames in `\Users\` paths, user SIDs (`S-1-5-21-…`), emails,
UNC hostnames, and MAC addresses. It deliberately **does not** redact IPv4 (in CBS/DISM the
dotted-quad shape is almost always a Windows *version* string like `10.0.0.0`) or Microsoft WinSxS
assembly names. See profile `notes` in the
[source tree](https://github.com/itlightning/sparklogs-redact/tree/main/packages/redact-core/patterns).

Pass custom `Detector[]` to `new Redactor(...)`, or extend the built-in registry. See
[`patterns/`](https://github.com/itlightning/sparklogs-redact/tree/main/packages/redact-core/patterns)
in the repo.

## Limitations

- Regex detectors may miss unanticipated PII and can false-positive (especially `generic` / `secret`).
- Profile `notes` document intentional skips (e.g. `windows-log` does not redact dotted-quad “version” strings).
- **Pseudonymization** keeps cross-token correlations within a pass; that can aid analysis but is not full anonymization.
- `scan() === []` is a useful gate, not a guarantee of publishable output.
- `MappingEngine.toJSON()` / CLI `--save-map` files hold **raw originals**; treat like secrets, never commit.

## License

[MIT](https://github.com/itlightning/sparklogs-redact/blob/main/LICENSE)
