# @sparklogs/redact-react

A reusable React wizard for **"redact locally, then upload"** flows. The user picks log files;
everything is classified and redacted **in the browser** with
[`@sparklogs/redact-core`](../redact-core); they preview exactly what will be sent (before/after with
per-value metadata) and fill in contact/consent details. Nothing is transmitted until they confirm —
and the actual network call is the host's, via `onSubmit`.

The component is **transport- and captcha-agnostic** (no endpoint or token baked in) and **themeable**
through CSS custom properties. Sensible neutral defaults ship out of the box.

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
  total})` drives the wizard's progress bar; `ctx.signal` aborts when the user clicks Cancel. (`fetch`
  cannot report upload progress — use `XMLHttpRequest`.) Resolve with `{ referenceId }` to show it on
  the receipt; reject to surface an error and let the user retry.
- **`consents`** are host-defined; the component renders the primary/optional grouping, enforces
  `implies` dependencies, and validates `required`. The payload carries `consents: Record<id, boolean>`.
- **`nudge`** (optional; omit to skip) shows a one-time modal on "continue" when an optional consent is
  left unchecked. **`copy`** overrides a few strings (rail title, reason label/placeholder, consent title).
- **`detailsSlot`** renders host content inside the "Your details" step — e.g. a Cloudflare Turnstile
  widget. The component never reads it; the host wires whatever it renders here into `onSubmit`.

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

## Theming

All visuals are driven by `--slup-*` custom properties (see [`src/styles.css`](src/styles.css) for the
full list). Override any of them on a wrapper to reskin — including redaction category colors
(`--slup-cat-username`, `--slup-cat-email`, …). No host design tokens are referenced.

```css
.my-upload-page .slup {
  --slup-accent: #5cadff;
  --slup-spark: #ffe800;
  --slup-cat-email: var(--brand-blue);
}
```

## How redaction metadata drives the preview

`@sparklogs/redact-core` returns, per replaced token, both the original-text offsets (`start`/`end`)
and the **output-text offsets** (`outStart`/`outEnd`). The preview slices the redacted text by the
output offsets to place highlight "pills" (the realistic fakes are not regex-recoverable), and — for
the local-only "reveal original" toggle — reads the raw value from the in-browser source via the
input offsets. Raw PII never leaves the browser and is never part of `onSubmit`'s payload.

## Local development (consuming this package without npm)

This is an unpublished workspace package. A consumer (e.g. a Docusaurus site) resolves it from a
sibling `sparklogs-redact` checkout via a bundler alias pointed at `dist/`. For fast iteration, run
the core and this package in watch mode so edits rebuild `dist` immediately:

```bash
# from the sparklogs-redact repo root
npm install
npm run build -w @sparklogs/redact-core
npx tsup --watch --config packages/redact-react/tsup.config.ts   # rebuilds dist on save
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
Safari 16.2+, Firefox 113+) for subtle surface tints — override the affected `--slup-*` variables if
you must support older engines. Requires the File/Blob and `TextDecoder` APIs; `crypto.randomUUID` is
used when available (secure context) with a graceful fallback.

## Styling contract

Styles are global, BEM-prefixed (`.slup__*`) under a single `.slup` root, and **fully scoped** to that
root (the package never styles host elements). The public, stable surface for theming is the
`--slup-*` custom properties and the `.slup` root class — these are intentionally global so hosts can
theme via variables and, if needed, override a class. Import the stylesheet once:
`import "@sparklogs/redact-react/styles.css"`.

## Large-file performance

- **Off-thread redaction** — the redaction pass runs in a Web Worker, so the main thread stays
  responsive on multi-MB inputs; the wizard shows per-file progress and a working Cancel. If a worker
  can't be constructed (CSP, unusual bundler), it transparently falls back to a synchronous in-thread
  pass. Override worker construction with `createWorker` if your bundler needs it.
- **Virtualized preview** — the default preview is a CodeMirror 6 viewer that only renders the visible
  viewport (the whole multi-MB document is never in the DOM at once). It loads in its own async chunk:
  CodeMirror is fetched only when the component is used (never on other pages), prefetched at idle after
  first paint so it's ready by the preview step, and is rendered lazily there. Swap it out entirely with
  `renderPreview` to drop the dependency.

### Deferred enhancements

- **Streaming / bounded memory**: the engine would decode and redact each file fully in memory. For inputs
  large enough to strain memory (hundreds of MB), a chunked/streaming pass would be needed; the
  detectors that span lines (e.g. PEM blocks) make this non-trivial. Not yet implemented.

## Acknowledgements

Thank you to the authors of these awesome packages:

- [**CodeMirror 6**](https://codemirror.dev) (by Marijn Haverbeke and contributors): powers the
  default virtualized before/after preview.
- [**Lucide Icons**](https://lucide.dev) (ISC): we inlined as as
  small SVG components. See [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md).

## License

[MIT](../../LICENSE). Third-party notices for redistributed material are in
[THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md).
