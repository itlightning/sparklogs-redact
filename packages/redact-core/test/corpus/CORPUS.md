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
| `pii-golden.jsonl` | This library's output for the PII corpus, one row per case, one column per pinned configuration (`generic`, `windows-log`, `union`). Local. |

## Provenance of the credential corpus

`corpus.jsonl`, `vrl-golden.txt` and `vrl-fixtures.jsonl` are produced in the SparkLogs source
library (private) by `tools/redaction-corpus.py` and `tools/test-redaction-corpus.py
--update-golden`, and carried here verbatim so both implementations answer to one standard.

`corpus.jsonl` and `vrl-golden.txt` are current as of source library commit
`7bb901b95b54cd41636c45538dfaff70cd28aeb1` (1472 cases).
Record the commit whenever they are refreshed: without it, a difference between the two
implementations cannot be told apart from a difference in when the copy was taken.

The copy here can lag that library.
Refreshing it is a deliberate change, not housekeeping: new cases move the credential golden and the
parity counts pinned in `corpus.test.ts`, and each moved line has to be read as a semantic diff (a
line that gained the credential marker is a leak; a line that lost the neighbour marker is new
over-redaction).
Refreshing `corpus.jsonl` without `vrl-golden.txt`, or the reverse, is what the loader's
length check exists to stop.

The credential corpus has one known gap.
It contains no JSON object whose **key** names a credential (`"password"`, `"pwd"`, `"secret"`,
`"token"`, `"apikey"`, `"api_key"`, `"accountkey"`, `"accesskey"`, `"credential"`, `"passphrase"`
with a string or numeric value), so no engine graded against it has a case for that family.
The shapes are carried in `pii-corpus.jsonl` (group `credential-json-key`) meanwhile, where they
assert only that the PII profiles leave configuration alone.
Closing the gap properly means extending the generator upstream.

One credential shape is worth knowing about before porting the patterns, because the redacted span is
wider than the value: `Use ConvertTo-SecureString instead of New-Object -String "X"`, where the span
takes the quotes with it.

Both engines that produced a golden here reach a fixed point on it after one pass.
A port reported needing a third pass on it and on the `--account-key=X; --metadata "env=Y;tier=1"`
line (in the over-redaction direction), so a port should verify convergence rather than assume one
pass settles.
The collector closed both at the pin above, by keeping the trailing `;` outside the connection-string
value and by requiring `-AsPlainText` before a bare positional counts as a secret.

That second change is a NARROWING, and the pin carries it: `ConvertTo-SecureString X` with no
`-AsPlainText` anywhere in the command is no longer a redaction upstream, because the cmdlet itself
rejects a plaintext argument without that flag.
One shape is exempt from that flag requirement: a quoted positional whose quote never closes before
the end of the line, which is how script-block logging splits a command across events.
A quote opened and abandoned cannot be prose, so the shape alone carries the redaction.
The refresh to this pin also brought five collector literals this library has no detector for (a
PowerShell credential constructor, an `-ArgumentList` credential pair, an encoded-command body, a
quoted key name before `=`, and unquoted values after compound secret flags).
Until those are ported, the leak and over-redaction counters in `corpus.test.ts` describe real
divergence rather than an empty set, and they are pinned at zero on purpose so the gap cannot be
absorbed silently.

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

### Columns

`generic` and `windows-log` are the two named profiles run on their own.

`union` is one pass over `secret` + `generic` + `windows-log` concatenated into a single detector
list, which is the configuration a server runs over free-form text.
It is not the same as redacting three times in a row: run separately, a credential detector and a
PII detector that claim overlapping text both fire, the second rewrites the first one's stand-in,
and the output depends on an ordering nobody wrote down.
Run together, one span resolution decides every overlap and the longer span wins once.
The concatenation repeats two detector names (`email` and `mac-address` are in both PII profiles);
duplicates produce identical spans, the first is accepted, the rest drop out as overlaps, and the
category is the same either way.

### Keep and credential

A case carrying `"keep": true` carries no personal data and must survive redaction
**byte-identical**.
That is where the corpus prices restraint: the validators (a 16-digit number that fails Luhn is an
order id), never-assigned shapes (SSN area 000, NANP area 000), placeholders a client wrote before
sending (`<host-1>`, `<user-2>`, `<client-A>`, `<ip-3>`), and this engine's own output.

A case carrying `"credential": true` carries a synthetic secret and no personal data.
The PII columns must leave it alone; the `union` column must take the secret out.
That pair is what proves the credential detectors are loaded in the union and nowhere else, so a
union assembled from the wrong list fails the gate instead of shipping a secret quietly.

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

Three more sections grade the `union` column specifically, since the credential corpus is a copy and
is refreshed upstream rather than extended here:

- **Line anchors.** An anchored assignment (`token=`, `api_key=`, `export access_token=`, quoted
  forms) immediately after each terminator, and a connection-string password immediately before one.
  A line-anchored pattern is only as good as the engine's idea of where a line starts and ends.
- **Case folding.** Keywords carrying U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S, with
  their plain-ASCII twins as controls.
- **Overlap resolution.** Lines where two detectors start at the same offset with different lengths,
  and lines where two differently-named detectors claim the identical span, with astral characters
  inside the longer span so the tiebreak is decided on offsets that do not survive a change of
  string representation.

### How this engine folds case

Measured, not assumed, because it is not uniform across the profile and a port has to reproduce the
mixture rather than pick one answer.

JavaScript's `i` flag on its own does **not** fold either character: `/password/i` does not match
`paſsword`, and `/token/i` does not match `toKen` spelt with the Kelvin sign. Adding the `u` flag
turns on full Unicode case folding and both match.

The detectors are not compiled with the same flags, so both behaviours are live at once:

| Detector | Flags | U+017F and U+212A in a keyword |
|---|---|---|
| `json-credential-value` | `iu` | folded onto ASCII, so the keyword matches |
| `conn-string-password` | `imu` | folded onto ASCII, so the keyword matches |
| `env-assignment-credential` | `im` | not folded |

The corpus pins both sides: `{"toKen":"…"}` and `{"ſecret":"…"}` are redacted, while the bare
`toKen=` and `ſecret=` assignments are not. Those bare cases are also blocked earlier, by an
ASCII-only key charset, so they do not isolate folding on their own; the JSON pair does.

A port that reads any of this differently produces a different golden line, which is what committing
a golden is for.

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
