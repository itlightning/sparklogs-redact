# Changelog

All notable changes to `@sparklogs/redact-core` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

Package versions in this monorepo are released in **lockstep** with `@sparklogs/redact-cli` and
`@sparklogs/redact-react` (same version number; see repo root README).

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
