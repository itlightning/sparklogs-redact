import { defineConfig } from "tsup";

// The Node CLI. Bundle @sparklogs/redact-core IN (noExternal) so the published dist/cli.js is
// self-contained and needs no runtime workspace/node_modules resolution — handy for the source-library
// PII-scan gate, which invokes it as `node .../redact-cli/dist/cli.js`. The core must be built first
// (its dist is what gets inlined here); the root `build` script orders core before cli.
export default defineConfig({
  entry: ["src/cli.ts"],
  format: ["esm"],
  target: "node20",
  noExternal: [/^@sparklogs\//],
  sourcemap: true,
  clean: true,
  splitting: false,
});
