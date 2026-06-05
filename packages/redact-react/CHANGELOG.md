# Changelog

All notable changes to `@sparklogs/redact-react` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

Package versions in this monorepo are released in **lockstep** with `@sparklogs/redact-core` and
`@sparklogs/redact-cli` (same version number; see repo root README).

## Unreleased

- **`UploadProgress.message`** — optional host-localized status line on `ctx.onProgress`; replaces the
  default send-step copy while the bar still uses `loaded`/`total`. Completion remains when `onSubmit`
  resolves (not when `loaded === total`).

## 0.1.0

Initial public release.

- **In-browser redact-then-upload wizard.** Classifies dropped files, redacts PII locally with
  `@sparklogs/redact-core`, previews the before/after, collects contact/consent details, and hands a
  redacted `UploadPayload` to a host-supplied `onSubmit` — nothing is transmitted until the user
  confirms, and the component bakes in no endpoint or captcha.
- **Data-driven consent.** Host-supplied `consents: ConsentItem[]` (plus `consentGroups`), rendered and
  validated generically, including transitive `implies` dependencies; the payload carries
  `consents: Record<id, boolean>`. Optional one-time pre-submit `nudge` and `copy` string overrides.
- **`onSubmit(payload, ctx)`** with `ctx.onProgress` (drives the upload progress bar) and `ctx.signal`
  (aborts on Cancel). Resolve with `{ referenceId }` to show it on the confirmation screen.
- **Virtualized before/after preview.** Default viewer is a lazy-loaded, viewport-virtualized
  CodeMirror 6 component with redaction "pills", a local-only reveal-original toggle, and a line-wrap
  toggle; replaceable via `renderPreview`. CodeMirror loads only when the component is used and is
  prefetched at idle so it is ready by the preview step.
- **Off-thread redaction.** Runs in a Web Worker with per-file progress and a working Cancel, falling
  back to a synchronous in-thread pass when a worker can't be constructed (`createWorker` overrides
  construction).
- **Themeable + accessible.** All visuals driven by scoped `--slup-*` CSS custom properties (no host
  tokens referenced). Associated form labels, `aria-invalid`/`aria-describedby` errors, a focus-trapped
  modal with Escape, `role="progressbar"` upload bar, polite live regions, and `aria-label`s on pills
  and file badges.
