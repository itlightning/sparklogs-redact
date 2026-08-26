# Changelog

All notable changes to `@sparklogs/redact-core` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

Package versions in this monorepo are released in **lockstep** with `@sparklogs/redact-cli` and
`@sparklogs/redact-react` (same version number; see repo root README).

## 0.3.0

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
