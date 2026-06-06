# @sparklogs/redact-react

[![RedactUploadWizard: redact locally, then upload](https://raw.githubusercontent.com/itlightning/sparklogs-redact/main/docs/assets/redact-react-demo.gif)](https://raw.githubusercontent.com/itlightning/sparklogs-redact/main/docs/assets/redact-react-demo.gif)

React wizard for **"redact locally, then upload"** flows. The user picks log files; everything is
classified and redacted **in the browser** with
[`@sparklogs/redact-core`](https://www.npmjs.com/package/@sparklogs/redact-core). They preview what
will be sent (before/after with per-value metadata) and fill in contact/consent details. Nothing is
transmitted until they confirm; the actual network call is the host's, via `onSubmit`.

**Transport- and captcha-agnostic** (no endpoint or token baked in). Theme via `--slup-*` CSS custom
properties on the `.slup` root (see [Theming](#theming) below).

From the [sparklogs-redact](https://github.com/itlightning/sparklogs-redact) monorepo. Depends on
[`@sparklogs/redact-core`](https://www.npmjs.com/package/@sparklogs/redact-core) at the same version.
CLI: [`@sparklogs/redact-cli`](https://www.npmjs.com/package/@sparklogs/redact-cli).

## Install

```bash
npm install @sparklogs/redact-react
```

Requires **React 18+** (`react` and `react-dom` as peer dependencies).

## Use

```tsx
import { RedactUploadWizard } from "@sparklogs/redact-react";
import "@sparklogs/redact-react/styles.css";

<RedactUploadWizard
  consents={[
    { id: "support", label: "Technical support", desc: "Diagnose my issue.", required: true, group: "primary" },
    { id: "product", label: "Improve the product", desc: "Retain to improve features.", group: "optional" },
    { id: "community", label: "Community library", desc: "Publish as an example.", group: "optional", implies: ["product"] },
  ]}
  consentGroups={{ optionalTag: "Optional", optionalHeading: "Help improve the product" }}
  nudge={{ whenUnchecked: "product", acceptSetsConsent: "product",
           title: "Help us learn from this?", body: "…",
           acceptLabel: "Yes", declineLabel: "No thanks" }}
  detailsSlot={<Turnstile siteKey={KEY} onSuccess={setTurnstileToken} />}
  onSubmit={async (payload, { onProgress, signal }) => {
    // host owns the request + any extra fields (e.g. a captcha token)
    const referenceId = await uploadWithProgress(payload, turnstileToken, onProgress, signal);
    return { referenceId }; // shown on the confirmation screen
  }}
/>;
```

- **`onSubmit(payload, ctx)`** receives the already-redacted `UploadPayload` (redacted text for text
  files, original blobs for allow-listed images/docs, plus a redaction summary). `ctx.onProgress({loaded,
  total, message?})` drives the wizard's progress bar and optional status line (`message` is
  host-localized); `ctx.signal` aborts when the user clicks Cancel. (`fetch` cannot report upload
  progress; use `XMLHttpRequest`.) Resolve with `{ referenceId }` to show it on
  the receipt; reject to surface an error and let the user retry.
- **`consents`** are host-defined; the component renders the primary/optional grouping, enforces
  `implies` dependencies, and validates `required`. The payload carries `consents: Record<id, boolean>`.
- **`nudge`** (optional; omit to skip) shows a one-time modal on "continue" when an optional consent is
  left unchecked. **`copy`** overrides a few strings (rail title, reason label/placeholder, consent title).
- **`detailsSlot`** renders host content inside the "Your details" step (e.g. a Cloudflare Turnstile
  widget). The component never reads it; the host wires whatever it renders here into `onSubmit`.

See `RedactUploadWizardProps` for policy knobs (`maxTotalBytes`, `maxFiles`, `imageExtensions`,
`docExtensions`, `profiles`), layout (`navStyle`, `previewStyle`), `allowRevealOriginal`, and
`categoryMeta` overrides.

- **`renderPreview(args)`** (optional) replaces the default text preview. By default the component
  lazy-loads a virtualized CodeMirror 6 viewer (only fetched at the preview step); provide this to
  render your own viewer (e.g. to drop the CodeMirror dependency). `args` (`PreviewRenderArgs`) carries
  the text, the redaction records with output offsets, the category resolver, and the reveal flag.
- **`createWorker()`** (optional) overrides how the redaction Web Worker is constructed, for bundlers
  that need specific syntax. The component bundles + instantiates its own worker by default and falls
  back to a synchronous in-thread pass if a worker can't be created, so this is rarely needed.

## Preview

The before/after view highlights redacted text using `outStart`/`outEnd` on each
`RedactionRecord` from `@sparklogs/redact-core`. The reveal-original toggle reads input offsets from
the in-browser source only. Raw PII never leaves the browser and is not part of `onSubmit`'s payload.
See [Redaction metadata](https://github.com/itlightning/sparklogs-redact/blob/main/packages/redact-core/README.md#redaction-metadata-for-beforeafter-uis)
in the core package.

## Theming

Import once: `import "@sparklogs/redact-react/styles.css"`.

Styles are BEM-prefixed (`.slup__*`) under a `.slup` root and do not style host elements outside that
root. The stable theming surface is `--slup-*` custom properties (full list in
[`styles.css` on GitHub](https://github.com/itlightning/sparklogs-redact/blob/main/packages/redact-react/src/styles.css)),
including per-category colors (`--slup-cat-username`, `--slup-cat-email`, …).

```css
.my-upload-page .slup {
  --slup-accent: #5cadff;
  --slup-spark: #ffe800;
  --slup-cat-email: var(--brand-blue);
}
```

## Accessibility

- Form fields use associated `<label htmlFor>` + `aria-required`, and errors link via
  `aria-invalid`/`aria-describedby` (and announce with `role="alert"`). The pre-submit modal traps
  focus, restores it on close, and closes on Escape (`role="dialog"` + `aria-labelledby`).
- Upload progress is a `role="progressbar"`; status changes ("Anonymizing…", upload state) use polite
  live regions; redaction-highlight pills and the skipped/not-redacted badges carry `aria-label`s.
- Keyboard-operable throughout (stepper steps, pills, file controls).

## Browser support

Targets modern evergreen browsers. The default stylesheet uses CSS `color-mix()` (Chrome/Edge 111+,
Safari 16.2+, Firefox 113+) for subtle surface tints; override the affected `--slup-*` variables if
you must support older engines. Requires the File/Blob and `TextDecoder` APIs; `crypto.randomUUID` is
used when available (secure context) with a graceful fallback.

## Large-file performance

- **Off-thread redaction**: the redaction pass runs in a Web Worker, so the main thread stays
  responsive on multi-MB inputs; the wizard shows per-file progress and a working Cancel. If a worker
  can't be constructed (CSP, unusual bundler), it transparently falls back to a synchronous in-thread
  pass. Override worker construction with `createWorker` if your bundler needs it.
- **Virtualized preview**: the default preview is a CodeMirror 6 viewer that only renders the visible
  viewport (the whole multi-MB document is never in the DOM at once). It loads in its own async chunk:
  CodeMirror is fetched only when the component is used, prefetched at idle after first paint, and
  rendered lazily at the preview step. Swap it out entirely with `renderPreview` to drop the dependency.

## Limitations

- Same detection gaps as [`@sparklogs/redact-core`](https://www.npmjs.com/package/@sparklogs/redact-core#limitations).
- **Allow-listed images/docs upload unredacted** (original blobs in `onSubmit`).
- **Reveal original** (default on) shows raw values in-browser only; disable via `allowRevealOriginal` if UX allows.
- Whole files decoded in memory (no streaming yet).
- Default `profiles` include `secret` (aggressive).
- English-only UI today (`copy` overrides a few strings; broader i18n planned).
- Not a compliance product; host owns consent copy, transport, and retention.

## Acknowledgements

- [**CodeMirror 6**](https://codemirror.dev): default virtualized before/after preview.
- [**Lucide Icons**](https://lucide.dev) (ISC): inlined as small SVG components. See
  [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md).

## License

[MIT](https://github.com/itlightning/sparklogs-redact/blob/main/LICENSE). Third-party notices:
[THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md).
