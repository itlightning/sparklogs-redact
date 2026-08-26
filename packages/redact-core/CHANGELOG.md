# Changelog

All notable changes to `@sparklogs/redact-core` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

Package versions in this monorepo are released in **lockstep** with `@sparklogs/redact-cli` and
`@sparklogs/redact-react` (same version number; see repo root README).

## 0.3.0

- **secret profile, line-terminator agreement**: value and neighbour classes now exclude
  U+2028, U+2029, U+0085, U+000B and U+000C alongside CR and LF, so a value bound agrees with what
  JavaScript itself treats as a line terminator. Before this, `Password=abc<U+2028>Server=keepme`
  ran the value past the separator and destroyed the neighbour; 20 of 25 probed shapes across five
  separators now keep it. `json-credential-value` is deliberately EXCLUDED from the widening: a JSON
  string may legally contain U+2028, U+2029 and U+0085, so bounding its value at one turned a
  redaction into a leak.
- **secret profile, `json-credential-value` key run is Unicode-aware**: the identifier prefix in
  front of the credential word now accepts any letter or digit rather than ASCII only, matching
  `conn-string-password`. `{"contraseña_password":"x"}` is redacted; `{"contraseña_passwordExpiry":"90"}`
  is still not.
- **Engine, cost is documented honestly**: what a pattern spends is quadratic in the length of an
  unbroken RUN its value branch can consume, not in the length of the line, and the comment and the
  performance test now say so. Accepted residual, measured: a single line carrying one unbroken run
  after a credential anchor costs 91 ms at 8 KB, 1.0 s at 32 KB and 35 s at 192 KB. Ordinary text
  never reaches it (400 KB of realistic log stays under 100 ms whether it arrives as one line or as
  thousands); the shape that does is a corrupt or hostile paste, and the remedy belongs in a caller
  that caps untrusted input.
- **Known, recorded rather than changed**: raw-library consumers pay BOM and encoding detection
  latency on every call through the byte-level entry points, which is visible only on very large
  inputs. A secret that itself contains the substring `REDACTED` is left alone, because that
  substring is how every detector recognises its own placeholder; this is the documented cost of
  keyless idempotency and is unchanged. The `jwt` detector's `safe` sentinel gate is what keeps a
  redacted JWT from being re-redacted into a different fake on a second pass.
- **secret profile, `env-assignment-credential` separator**: a run of spaces or tabs is now allowed
  on either side of the `=` or `:`, so the `.ini` spelling `token = value` and an aligned config
  column are redacted. A run of spaces and tabs is safe to allow because it cannot reach off the
  line; the detector this replaces crossed a line break because its separator was `\s*`, and `\s`
  contains `\n`. That was a different character class, not a different quantity of whitespace.
  Pipe-delimited table columns are still not assignments.
- **secret profile, `env-assignment-credential` reads a syslog process tag**: the same assignment
  arrives two ways, read from a config file and forwarded through a log line, so the key may now
  also follow a `tag[pid]: ` prefix (`app[1]: `, `sshd[1234]: `). The alternative is narrow on
  purpose: a word character immediately before the bracket, digits inside it, `]:` and exactly one
  space. A generic `word: ` prefix is NOT admitted, because that is the prose surface that killed
  the detector this replaces, and the narrowing is what keeps `Retry [3]: `, `step [2]: `,
  `[ERROR]: ` and `[2026-08-25 10:00:00]: ` out. A footnote-shaped `note[1]: ` does satisfy it.
- **Tests, deliberate misses are now priced**: unsigiled credential assignments MID-LINE with no
  process tag are not redacted, which is the cost of retiring the bare-word detector. The generated
  corpus is structurally blind to that shape, so retiring it moved zero cases and looked free. Three
  such shapes are now pinned in the corpus as unchanged lines, so the trade is visible in the golden
  and reclaiming it has to be argued for rather than slipped in.
- **secret profile, `curl-user-password-single-quoted` and a single-quoted value branch**: both curl
  detectors read only double quotes, so `curl -u 'admin:hunter2'`, `curl --user 'admin:hunter2'` and
  `curl -u admin:'hunter 2'` left the whole credential on the line. A POSIX shell quotes with `'` at
  least as often as with `"`, and every other family here already reads both.
- **secret profile, new `env-assignment-credential`**: the narrow replacement for the retired
  bare-word detector. It covers `api_key=`, `token:`, `secret=`, `client_secret=`, `access_key=` and
  the access, auth, refresh and session token spellings, but ONLY where the key begins the line
  (indentation and an `export` or `set` prefix allowed), which is the `.env`, `.ini` and YAML shape.
  The line-start anchor is what separates a field name from the same word inside a sentence, and it
  is what the retired detector lacked. Three further rules narrow it: the key ends at the separator,
  the separator carries no whitespace run (`=` takes none, `:` takes at most one space, so nothing
  reaches across a line break), and the value is at least eight characters so a boolean or a
  placeholder is not a credential. An unquoted value stops at a `;` so the connection-string
  grammar and its neighbouring keys survive. Known and accepted: a sentence that BEGINS with one of
  these words and a colon loses its first word when that word is eight characters or longer; the
  cases are pinned in the tests.
- **secret profile, `secret-assignment` retired**: the broad `key = value` detector anchored on a
  bare word with no sigil and a whitespace-tolerant separator, and it was the source of every
  remaining false positive the corpus finds. It redacted `publicKeyToken=`, it redacted `token=`
  inside the sentence "The token=X was rejected by the API", and its separator crossed a LINE BREAK
  and ate the first token of the following line. The precise detectors added above cover the same
  credentials from a real signal. One consequence is deliberate and worth knowing: the LOWERCASE
  unsigiled spellings `api_key=`, `token=` and `secret=` are no longer matched, while their
  uppercase environment-variable spellings, their sigil-prefixed flag forms, their JSON forms and
  the connection-string vocabulary all are.
- **secret profile, the positional command-line families**: `net-user-password`,
  `net-use-password`, `bitsadmin-credential` and `rasdial-password`. No flag names the credential in
  any of these, so the anchor is the tool name plus the arguments in front of the value, and the
  documented innocent variants (`/add`, the `*` prompt, `/domain`, the query form, `/persistent:`,
  `/delete`, `/user:`, `/disconnect`) keep their text. Each value branch carries its OWN terminator
  rather than sharing one: a quoted run that cannot close can always shorten itself to a shorter
  valid run, and a shared terminator lets the engine back off into exactly that, leaving a
  placeholder with the rest of the password after it.
- **secret profile, PowerShell, registry and curl detectors**:
  - `powershell-securestring-argument` and `powershell-securestring-string-argument`: the plaintext
    handed to `ConvertTo-SecureString`, positionally or through `-String`. Two detectors, not one
    with an optional hop: an optional hop in front of a zero-width anchor matches both with and
    without it and would redact twice.
  - `powershell-securestring-pipe`: a quoted literal piped into the same cmdlet.
  - `powershell-secret-parameter` and its single-quoted twin: the literal given to `-Password`,
    `-ApiKey`, `-ClientSecret`, `-SasToken`, `-Token` and the rest. The match is the content
    BETWEEN the quotes, so the quoting around the value survives.
  - `registry-add-credential`: `reg add` with a `/v` value name ending in a credential word and a
    `/d` value of at least two characters. All three parts are required, which is what makes a
    suffix rule safe and what keeps `DisableChangePassword /d 1` out.
  - `curl-user-password` and its quoted form: the password half of `curl -u user:password`. The
    username is in the anchor rather than the match, so it survives.
- **secret profile, five new command-line detectors**, all anchored on a tool name or a
  proper-noun grammar rather than on a flag letter:
  - `msi-property-credential`: a credential passed as an installer public property
    (`msiexec /i agent.msi /qn TOKEN=...`), which is how an agent receives its tenant secret at
    install time. Case-sensitive, because only an all-uppercase property can be set from a command
    line and that is what keeps the detector off the assembly-identity fields.
  - `http-auth-credential`: the credential in an `Authorization` or `Proxy-Authorization` header,
    for every scheme that carries one (Bearer, Basic, Digest, Negotiate, NTLM, ApiKey).
  - `putty-password-flag`: `-pw` on `plink`, `pscp`, `psftp` and `putty`. `-pwfile` names a path
    and keeps it.
  - `sql-cli-password-flag`: uppercase `-P` on `sqlcmd`, `osql`, `bcp` and `isql`. Lowercase `-p`
    on those tools prints statistics and is left alone, so the detector is case-sensitive.
  - `command-flag-password`: a sigil-prefixed word flag (`--pass=`, `/pwd:`, `-passphrase=`,
    `-token=`). The sigil and the immediate separator are what make a word list this broad safe.
- **secret profile, `auth-bearer` and `auth-basic` retired**: they anchored on the scheme word
  alone, which is an ordinary English word, and were measured firing on prose such as "the
  Authorization header was missing" and "bearer slk_ is one character short".
  `http-auth-credential` covers the same credentials with the header name in the anchor.
- **secret profile, vendor token prefixes**: the GitHub, GitHub fine-grained, GitLab, Google and
  npm rows no longer pin an exact body width and no longer require a word boundary after the body.
  Both were leaks: a vendor mints tokens at whatever width it likes and has changed those widths, so
  an exact width misses every other size, and a base64url body ending in `-` or `_` has no word
  boundary after it at all, which dropped the token entirely. Each row now takes the smallest minted
  width as a floor.
- **secret profile, new SparkLogs token rows**: `sl_<region>_` ingest keys, `slk_` managed-agent
  keys and `slr_` refresh tokens are redacted, with the region label kept because it names a data
  residency boundary rather than part of the secret.
- **secret profile, `slack-token`**: the `xoxe-` app-configuration prefix is recognised.
- **secret profile, `conn-string-url-password`**: the userinfo username run is no longer capped at
  64 characters. The cap was a leak: past it the whole match failed and the password after the `:`
  shipped verbatim.
- **secret profile, `conn-string-password` rewritten**: one detector now covers both the
  connection-string and the free-prose/command-line forms, with the key vocabulary widened to
  `passwd`, `client-secret` and the hyphen and underscore spellings of the account, access and
  shared-access keys.
  - A doubled quote inside a quoted value no longer ends it early, so `--password="a""b"` is
    redacted whole instead of leaving `"b"` behind.
  - A value whose quote never closes (`--password="ab --site Acme`) is redacted to the end of the
    line instead of being missed entirely, and a value that OPENS with a doubled quote
    (`Password=""x"""`) no longer matches the empty quote pair and ships the rest.
  - The plausible-next-key run is unbounded and Unicode-aware. A neighbour key longer than the old
    30-character cap, or spelt in a non-ASCII script, was not recognised as a key, so the value ate
    to the end of the line and destroyed the neighbour the detector exists to preserve.
  - A value on a command line stops before the next flag, so `--account-key=K; --metadata
    "env=prod;tier=1"` no longer runs across the rest of the command.
  - A bare value now consumes interior quotes (`password=don't` goes whole) and backs off a
    trailing quote so the surrounding quoting stays balanced.
- **Engine, long-line cost**: every command-line pattern now opens with a zero-width test that its
  value does not start with whitespace, ahead of the unbounded look-behind that anchors it. A
  variable-length separator otherwise offers the engine one start position per space and each one
  re-scans the line, which is eight times the time on a pathological single-line input.
  `test/performance.test.ts` is the tripwire, for an ordinary large paste and for one very long line.
- **Engine, deterministic tie-breaks**: when two detectors claim the identical span, the winner (and
  therefore the fake's category) is now decided by detector name rather than by the order the spans
  happened to be collected in. `scan()` results are ordered by line, column, end and detector name
  for the same reason.

## 0.2.4

- **secret profile, new `json-credential-value` detector**: a credential in a JSON object member is
  now redacted (`"sessionpassword":"..."`, `"password":"..."`, `"apiToken": "..."`,
  `"client_secret":"..."`). A JSON body carries no `=`, so neither connection-string detector could
  see it, and a REST or RPC result body is exactly where a session credential travels in full. The
  key must END with the credential word, so a key that merely CONTAINS one keeps its value:
  `"passwordExpiryDays"`, `"passwordPolicy"`, `"tokenCount"`, `"lastPasswordChange"` and
  `"accesskeyid"` (the public half of an AWS key pair) are not matched. The key list is wider than
  the connection-string one (`token`, `secret`, `credential`, `passphrase` added) because a quoted
  key immediately before a `:` is a field name rather than a word in a sentence. Only the value
  between the quotes is replaced, so the object stays parseable JSON, and JSON escapes are honoured
  so a `\"` inside a value cannot end the match early. An unquoted value (a JSON number,
  `true`/`false`/`null`) is not matched: the engine replaces a matched span with a placeholder and
  cannot re-quote it, so redacting one would emit invalid JSON. Object and array values are not
  matched either, since finding their end needs balanced counting.

## 0.2.3

- **secret profile, `conn-string-password`**: the key alternation now allows an optional
  `[A-Za-z_]*` identifier prefix, so `SecretAccessKey=` and `AwsSecretAccessKey=` are matched. A `\b`
  anchor does not fire between a lowercase letter and an uppercase one, so the alternation could
  never start mid-identifier and the AWS form was missed: that is the secret half of an AWS key pair
  and a common application-log shape, so the gap leaked a live credential. The key must still sit
  immediately before the `=`, so configuration values keep their own names:
  `MyPasswordPolicy=strict`, `PasswordExpiryDays=90`, `LastPasswordChange=2026` and `accesskeyid=`
  (the public half of the AWS pair, an identifier rather than a secret) are not matched.

## 0.2.2

- **secret profile, `conn-string-password`**: closed three credential leaks. A password containing
  spaces (`Password=P@ss w0rd!`) was truncated at the first space and the remainder survived; a
  quoted value (`Password="quoted;pw"`) did not match at all; and Azure `AccountKey=`,
  `AccessKey=` and `SharedAccessSignature=` were not covered. The value now terminates at a `;` only
  when a plausible next key follows, or at the matching quote, which is what the connection-string
  grammar actually specifies. Space and semicolon tolerance apply only inside connection-string
  context: a bare `password=` in free prose keeps the conservative whitespace-terminated form, so an
  ordinary log sentence loses the credential and nothing around it.

## 0.2.1

- **README**: consumer-focused docs; install section, npm links (no monorepo contributor copy).

## 0.2.0

Monorepo lockstep release; no functional changes in this package.

## 0.1.0

Initial public release.

- Isomorphic detection, consistent-mapping engine, and residual-PII scanner.
- Portable JSON detection profiles (`windows-log`, `generic`, `secret`).
