# Changelog

All notable changes to `@sparklogs/redact-core` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

Package versions in this monorepo are released in **lockstep** with `@sparklogs/redact-cli` and
`@sparklogs/redact-react` (same version number; see repo root README).

## Unreleased

- **Engine, `lineBounded` detectors**: a detector may now declare that no match, lookbehind or
  lookahead of its pattern can cross a line break, and the engine then runs it against one line at a
  time instead of the whole document. JavaScript regexes backtrack, so their cost is quadratic in
  the length of the haystack they scan; bounding that haystack to a line bounds the worst case a
  pasted document can produce. Detection is unchanged: `test/line-feeding.test.ts` proves every
  declaration by comparing line-at-a-time and whole-document detection over both corpora, and by
  showing that a pattern WITHOUT the declaration still spans lines.
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
