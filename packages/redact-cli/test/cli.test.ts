import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { test } from "node:test";

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const cliJs = join(pkgRoot, "dist", "cli.js");
const cleanFixture = join(pkgRoot, "..", "..", "test", "fixtures", "clean", "sample.log");

/** spawnSync stdout/stderr are strings when `encoding` is set; narrow for strict tsc. */
function asText(chunk: ReturnType<typeof spawnSync>["stdout"]): string {
  return typeof chunk === "string" ? chunk : chunk ? chunk.toString("utf8") : "";
}

function runCli(args: string[]): ReturnType<typeof spawnSync> {
  if (!existsSync(cliJs)) {
    throw new Error(
      `CLI bundle missing at ${cliJs} — run "npm run build -w @sparklogs/redact-cli" (or "make build") first`,
    );
  }
  return spawnSync(process.execPath, [cliJs, ...args], {
    encoding: "utf8",
    env: { ...process.env, NODE_NO_WARNINGS: "1" },
  });
}

test("profiles exits 0 and lists windows-log", () => {
  const r = runCli(["profiles"]);
  assert.equal(r.status, 0, asText(r.stderr) || asText(r.stdout));
  assert.match(asText(r.stdout), /windows-log/);
});

test("scan clean fixture exits 0 (no residual PII)", () => {
  assert.ok(existsSync(cleanFixture), `missing fixture: ${cleanFixture}`);
  const r = runCli(["scan", cleanFixture, "--quiet"]);
  assert.equal(r.status, 0, asText(r.stderr) || asText(r.stdout));
});

test("redact stdin/stdout round-trip exits 0", () => {
  const input = "Package version 10.0.0.0 installed\n";
  const r = spawnSync(process.execPath, [cliJs, "redact", "-", "-o", "-"], {
    encoding: "utf8",
    input,
    env: { ...process.env, NODE_NO_WARNINGS: "1" },
  });
  assert.equal(r.status, 0, asText(r.stderr) || asText(r.stdout));
  assert.ok(asText(r.stdout).includes("10.0.0.0"), "benign version string preserved");
});
