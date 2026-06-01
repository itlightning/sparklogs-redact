import { defineConfig } from "tsup";

// The isomorphic library. Single ESM entry + type declarations. The JSON pattern specs are imported
// at runtime-resolved paths, so bundle them in for a self-contained dist (they're also shipped as
// data files via package.json "files" for consumers that want to read them directly).
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node18",
  dts: { entry: { index: "src/index.ts" } },
  sourcemap: true,
  clean: true,
  splitting: false,
  loader: { ".json": "json" },
});
