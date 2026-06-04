import { defineConfig } from "tsup";

// Component library bundle. React (peer) and @sparklogs/redact-core (dependency) stay EXTERNAL so the
// host app dedupes them / resolves them through its own alias. The default stylesheet is copied to
// dist on success; consumers import "@sparklogs/redact-react/styles.css".
export default defineConfig({
  // The worker is a second entry so it ships as dist/redact.worker.js, referenced from the main bundle
  // via `new Worker(new URL("./redact.worker.js", import.meta.url))` — the consumer's bundler emits it.
  entry: ["src/index.ts", "src/redact.worker.ts"],
  format: ["esm"],
  target: "es2022",
  dts: { entry: { index: "src/index.ts" } },
  external: ["react", "react-dom", "react/jsx-runtime"],
  // CodeMirror stays EXTERNAL (it's a normal `dependency`): our published `dist` references it via a
  // bare `import` rather than embedding its source, so the consumer's bundler tree-shakes + dedupes it
  // and carries its MIT notice — we don't redistribute CodeMirror's bytes. `splitting` keeps the CM6
  // import inside the lazy `import()` chunk from StepRedact, so the host's bundler only pulls CM6 into
  // the preview-step async chunk (and never onto pages that don't use the component).
  splitting: true,
  sourcemap: true,
  clean: true,
  onSuccess: "cp src/styles.css dist/styles.css",
});
