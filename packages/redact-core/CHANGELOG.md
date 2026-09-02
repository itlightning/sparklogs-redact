# Changelog

All notable changes to `@sparklogs/redact-core` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

Package versions in this monorepo are released in **lockstep** with `@sparklogs/redact-cli` and
`@sparklogs/redact-react` (same version number; see repo root README).

## Unreleased

### Added

- Command-line: `psexec-password-flag` (`psexec` / `psexec64` `-p`, attached or spaced), `mysql-password-flag` (`mysql` / `mysqldump` `-p<value>`, attached only), `schtasks-runas-password` (`/RP value` and `/RP:value`). 42 secret-profile detectors.

## 0.3.0

`secret` profile covers command-line and connection-string credentials (same family as the SparkLogs collector). 39 secret-profile detectors.

### Added

- Command-line: `msi-property-credential` (all-caps installer properties), `http-auth-credential` (`Authorization` / `Proxy-Authorization`), `putty-password-flag`, `sql-cli-password-flag` (uppercase `-P` only), `command-flag-password` (`--pass=`, `/pwd:`, …).
- Positional (tool name + preceding args, innocent variants kept): `net-user-password`, `net-use-password`, `bitsadmin-credential`, `rasdial-password`. Each value branch has its own terminator so a truncated quote cannot leave a password suffix.
- PowerShell: `ConvertTo-SecureString` (positional, `-String`, pipe); `-Password` / `-ApiKey` / `-ClientSecret` / `-SasToken` / `-Token` (quoted content only, quotes kept). Split into separate detectors: an optional hop on a zero-width anchor would match twice.
- `registry-add-credential`: `reg add` with a `/v` name ending in a credential word and a `/d` value of 2+ chars. Keeps `DisableChangePassword /d 1`.
- `curl-user-password` (and quoted / single-quoted twins): password half of `curl -u` / `--user`. Username stays. Single quotes were a leak (`curl -u 'admin:…'`).
- `env-assignment-credential`: line-start (indent / `export` / `set` ok) or `tag[pid]: ` syslog prefix. Spaces/tabs around `=` or `:`. Value ≥ 8 chars; unquoted value stops at `;`. Pipe tables and `Retry [3]: ` / `[ERROR]: ` / timestamp prefixes stay out; `note[1]: ` matches. Replaces `secret-assignment`.
- SparkLogs tokens: `sl_<region>_` ingest keys (region kept), `slk_` agent keys, `slr_` refresh tokens. `slack-token` also matches `xoxe-`.

### Changed

- `conn-string-password`: one detector for connection-string and prose/flag forms. Keys include `passwd`, `client-secret`, and hyphen/underscore account/access/SAS spellings.
  - Doubled quotes no longer truncate (`--password="a""b"`).
  - Unterminated quote eats to end of line.
  - Opening `""` is not treated as an empty value.
  - Neighbour-key run is unbounded and Unicode-aware (old 30-char / ASCII cap ate past the next key).
  - Command-line values stop before the next flag.
  - Bare values consume interior quotes (`password=don't`) and back off a trailing quote.
- `conn-string-url-password`: username run no longer capped at 64 chars (the cap dropped the whole match and leaked the password).
- Vendor token rows (GitHub, GitLab, Google, npm): minimum body width, no exact length, no trailing `\b` (both were leaks on real mint widths and on bodies ending `-`/`_`).
- `json-credential-value`: identifier prefix is Unicode, matching `conn-string-password`.

### Removed

- `secret-assignment` (bare `key = value`). It hit `publicKeyToken=`, in-sentence `token=`, and crossed line breaks. Lowercase unsigiled `api_key=` / `token=` / `secret=` mid-line are no longer redacted; uppercase env names, flags, JSON, and connection-string keys still are. Three mid-line misses are pinned in the corpus golden.
- `auth-bearer` and `auth-basic` (scheme word alone fired on prose). Replaced by `http-auth-credential`.

### Engine

- Value/neighbour classes treat U+2028, U+2029, U+0085, U+000B, U+000C as line ends, matching JavaScript. `json-credential-value` is excluded: those code points are legal inside a JSON string, so bounding there leaked.
- Command-line patterns test that the value does not start with whitespace before the unbounded lookbehind (avoids one start position per space).
- Identical-span ties break on detector name, not collection order. `scan()` sorts by line, column, end, name.

### Limits (accepted)

- Quadratic in the length of an unbroken run after a credential anchor, not in line length. Measured: 91 ms at 8 KB, 1.0 s at 32 KB, 35 s at 192 KB. Ordinary 400 KB logs stay under 100 ms. Cap hostile input in the caller; core stays uncapped.
- Byte-level entry points pay BOM/encoding detection on every call (visible only on very large inputs).
- A secret containing the substring `REDACTED` is left alone (`safe` sentinel / idempotency). JWT uses the same gate.
- `env-assignment-credential`: a sentence that *starts* with a covered word plus a colon can lose that word when the rest is ≥ 8 chars. Pinned in tests.

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
