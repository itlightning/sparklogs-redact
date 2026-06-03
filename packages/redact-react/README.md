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

## Deferred (not in v1)

- **Web Worker redaction** — `runRedaction` is eager/in-memory; fine for typical logs. Move it to a
  worker for multi-MB inputs so the main thread stays responsive.
- **Virtualized preview** — the before/after view renders the whole file; swap the `<pre>` for a
  windowed/virtualized text view (CodeMirror 6 / `react-window`) for very large files.

## License

[MIT](../../LICENSE)
