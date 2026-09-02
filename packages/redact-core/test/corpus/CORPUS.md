# Shared redaction corpora

Two corpora live here, and they are graded for different reasons.

The **credential corpus** is a copy.
It grades this library against a second implementation of the same credential families that runs in
the SparkLogs source library, on the collector, in VRL.
Its golden is that implementation's output, so a diff says which of the two moved.

The **PII corpus** is local.
There is no second implementation of the `generic` and `windows-log` profiles to copy a golden from,
so its golden is this engine's own output, and it is the contract that any port of these profiles is
held to.

Every value in both corpora is **synthetic**.
No line came from a real log.

## Files

| File | What it is |
|---|---|
| `corpus.jsonl` | Generated adversarial credential sweep, one `{"message": ...}` object per line, in the generator's fixed emission order. Copied from the SparkLogs source library. |
| `vrl-golden.txt` | The collector's output for those cases, one JSON-encoded string per line, positionally aligned with `corpus.jsonl`. Copied from the same place. |
| `vrl-fixtures.jsonl` | Hand-written credential cases as `{case, input, vrl}` triples. Copied from the same place. |
| `deliberate-misses.jsonl` | Credential assignments this library knowingly does not redact. Local, not copied. |
| `js-golden.txt` | This library's output for every credential case, with spans normalised to `<redacted>`. |
| `pii-corpus.jsonl` | Generated PII corpus, one `{"case", "message", "keep"?}` object per line. Local. |
| `pii-golden.jsonl` | This library's PII output, one row per case, one column per pinned profile. Local. |

## Provenance of the credential corpus

`corpus.jsonl`, `vrl-golden.txt` and `vrl-fixtures.jsonl` are produced in the SparkLogs source
library (private) by `tools/redaction-corpus.py` and `tools/test-redaction-corpus.py
--update-golden`, and carried here verbatim so both implementations answer to one standard.

The copy here can lag that library.
Refreshing it is a deliberate change, not housekeeping: new cases move the credential golden and the
parity counts pinned in `corpus.test.ts`, and each moved line has to be read as a semantic diff (a
line that gained the credential marker is a leak; a line that lost the neighbour marker is new
over-redaction).

The credential corpus has one known gap.
It contains no JSON object whose **key** names a credential (`"password"`, `"pwd"`, `"secret"`,
`"token"`, `"apikey"`, `"api_key"`, `"accountkey"`, `"accesskey"`, `"credential"`, `"passphrase"`
with a string or numeric value), so no engine graded against it has a case for that family.
The shapes are carried in `pii-corpus.jsonl` (group `credential-json-key`) meanwhile, where they
assert only that the PII profiles leave configuration alone.
Closing the gap properly means extending the generator upstream.

Two credential shapes are worth knowing about before porting the patterns, because the redacted span
is wider than the value:

- `--account-key=X; --metadata "env=Y;tier=1"` - the span runs through the trailing `;`.
- `Use ConvertTo-SecureString instead of New-Object -String "X"` - the span takes the quotes with it.

Both reach a fixed point after one pass in this engine.
A port reported needing a third pass on them (in the over-redaction direction), so a port should
verify convergence rather than assume one pass settles.

## The PII corpus

`pii-corpus.jsonl` is generated, not typed, so that every value is exercised in every context: bare,
after a label, quoted, mid-sentence, in a `key=value` field, and at the end of a line that ends in a
newline character.
`scripts/gen-pii-corpus.mjs` crosses a table of values with a table of contexts; adding a value adds
it to every context at once.

Values are drawn from documentation and reserved ranges only.
Ranges this engine treats as **already redacted** (RFC 5737 TEST-NET, RFC 3849 `2001:db8::/32`,
`example.com`, `example.invalid`) cannot double as detection inputs, so detection cases use other
never-routed space: RFC 2544 benchmarking (`198.18.0.0/15`), RFC 6598 shared address space
(`100.64.0.0/10`), RFC 1918 private space, RFC 4193 unique-local IPv6, and the RFC 2606
`example.net` / `example.org` domains.
Card numbers are the vendors' published test numbers.

A case carrying `"keep": true` must survive redaction **byte-identical under every profile**.
That is where the corpus prices restraint: the validators (a 16-digit number that fails Luhn is an
order id), never-assigned shapes (SSN area 000, NANP area 000), placeholders a client wrote before
sending (`<host-1>`, `<user-2>`, `<client-A>`, `<ip-3>`), and this engine's own output.

Some cases exist to expose **regex dialect** differences, because the same patterns are ported to
engines whose `\d`, `\b` and end-of-line semantics are wider than JavaScript's:

- SSN-shaped and card-shaped runs written in fullwidth and Arabic-Indic digits, which must not match.
- An accented letter glued to a MAC address, where a Unicode-aware `\b` stops matching.
- A token immediately before each line terminator the engines rank differently: `\n`, a bare `\r`,
  `\r\n`, U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR. JavaScript's `.` refuses all five
  and its `$` means end of input; .NET-derived engines exclude only `\n` from `.` and let `$` match
  before a trailing one; RE2 draws the line elsewhere again. One case per terminator also puts a
  second copy of the token after U+2028, so both sides of the break are graded.
- Characters above U+FFFF beside a token and inside one (an emoji and a supplementary-plane letter).
  They are two UTF-16 code units here, four UTF-8 bytes in Go and one rune in Rust, so an offset
  this engine reports is not that offset anywhere else, and a port that carries offsets rather than
  recomputing them cuts a token in half. Some of these lines put an IPv4 address inside an IPv6 one,
  where two detectors claim overlapping spans and the longer has to win.

A port that reads those differently produces a different golden line, which is what committing a
golden is for.

## Regenerating

```bash
npm run regen-pii-corpus     # rewrite pii-corpus.jsonl from scripts/gen-pii-corpus.mjs
npm run regen-pii-golden     # rewrite pii-golden.jsonl from the current engine
npm run regen-corpus-golden  # rewrite js-golden.txt (credential corpus)
```

Read the diff before committing it.
A golden nobody read is worth nothing.

## Using these corpora from another language

Nothing here is published to npm.
Consumers check this repo out at a **pinned commit SHA** and run their own parity tests against
`packages/redact-core/test/corpus/*`, comparing their engine's output to the committed golden line
for line.
The pattern JSON in `packages/redact-core/patterns/` is the other half of that contract: an
implementation that embeds a copy of those files should assert the copy equals the checkout's at the
pin.
