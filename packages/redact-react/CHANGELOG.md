# Changelog

All notable changes to `@sparklogs/redact-react` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

Package versions in this monorepo are released in **lockstep** with `@sparklogs/redact-core` and
`@sparklogs/redact-cli` (same version number; see repo root README).

## 0.2.1

- **README**: consumer-focused docs; linked demo GIF on npm, install/use sections, npm links (no monorepo/sibling copy).
- **Preview toolbar**: position counter (`N / M`) left of prev/next buttons; centered with 10ch min-width when visible; hidden until first jump.

## 0.2.0

- **`UploadProgress.message`**: optional host-localized status on `ctx.onProgress`; replaces default
  send-step copy while the bar still uses `loaded`/`total`. Completion when `onSubmit` resolves (not
  when `loaded === total`).
- **Export `UploadProgress`** from the package entrypoint.
- **Wizard copy**: clearer step hints, headers, and footers (on-device redaction, upload timing, keep
  tab open until confirmation).
- **Send step**: host `message` drives status text and progress bar `aria-label`; footer copy updated.
- **Locked rule pills**: selected styling (was dashed/muted).

## 0.1.0

Initial public release.

- **In-browser redact-then-upload wizard**: classifies dropped files, redacts PII locally with
  `@sparklogs/redact-core`, previews before/after, collects contact and consent details, and hands a
  redacted `UploadPayload` to a host-supplied `onSubmit`; nothing is transmitted until the user
  confirms. No endpoint or captcha baked in.
- **Data-driven consent**: host-supplied `consents: ConsentItem[]` (plus `consentGroups`), rendered and
  validated generically, including transitive `implies` dependencies; payload carries
  `consents: Record<id, boolean>`. Optional one-time pre-submit `nudge` and `copy` string overrides.
- **`onSubmit(payload, ctx)`**: `ctx.onProgress` drives the upload progress bar; `ctx.signal` aborts on
  Cancel. Resolve with `{ referenceId }` for the confirmation screen.
- **Virtualized before/after preview**: default viewer is lazy-loaded, viewport-virtualized CodeMirror 6
  with redaction pills, local-only reveal-original toggle, and line-wrap toggle; replaceable via
  `renderPreview`. CodeMirror loads on use and prefetches at idle for the preview step.
- **Off-thread redaction**: runs in a Web Worker with per-file progress and working Cancel; falls back to
  a synchronous in-thread pass when a worker can't be constructed (`createWorker` overrides
  construction).
- **Themeable and accessible**: visuals use scoped `--slup-*` CSS custom properties (no host tokens).
  Form labels, `aria-invalid`/`aria-describedby` errors, focus-trapped modal with Escape,
  `role="progressbar"` upload bar, polite live regions, and `aria-label`s on pills and file badges.
