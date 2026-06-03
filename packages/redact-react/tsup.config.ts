import { defineConfig } from "tsup";

// Component library bundle. React (peer) and @sparklogs/redact-core (dependency) stay EXTERNAL so the
// host app dedupes them / resolves them through its own alias. The default stylesheet is copied to
// dist on success; consumers import "@sparklogs/redact-react/styles.css".
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "es2022",
  dts: { entry: { index: "src/index.ts" } },
  external: ["react", "react-dom", "react/jsx-runtime"],
  sourcemap: true,
  clean: true,
  splitting: false,
  onSuccess: "cp src/styles.css dist/styles.css",
});
