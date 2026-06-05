import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { test } from "node:test";

const pkgRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const cliJs = join(pkgRoot, "dist", "cli.js");
const cleanFixture = join(pkgRoot, "..", "..", "test", "fixtures", "clean", "sample.fixture");

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

function writeTempLog(name: string, text: string): string {
  const dir = mkdtempSync(join(tmpdir(), "redact-cli-"));
  const path = join(dir, name);
  writeFileSync(path, text, "utf8");
  return path;
}

test("scan: /Users/Default/ in CBS-style path is clean (profile safelist)", () => {
  const path = writeTempLog(
    "cbs.log",
    "GLOBALROOT/Device/HarddiskVolumeShadowCopy6/Users/Default/ntuser.dat\n",
  );
  const r = runCli(["scan", path, "--quiet"]);
  assert.equal(r.status, 0, asText(r.stderr) || asText(r.stdout));
});

test("scan: --disable-categories skips username but still catches secrets", () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const userOnly = writeTempLog("user.log", "path \\Users\\realperson\\docs\n");
  const secret = writeTempLog("secret.log", `token ${jwt}\n`);

  const rUser = runCli([
    "scan",
    userOnly,
    "--quiet",
    "--disable-categories",
    "username,host",
  ]);
  assert.equal(rUser.status, 0, asText(rUser.stderr) || asText(rUser.stdout));

  const rSecret = runCli([
    "scan",
    secret,
    "--quiet",
    "--disable-categories",
    "username,host",
  ]);
  assert.equal(rSecret.status, 1, "JWT should still be flagged");

  const userSid = writeTempLog("sid.log", "owner S-1-5-21-1004336348-1177238915-682003330-1001\n");
  const rSid = runCli(["scan", userSid, "--quiet", "--disable-categories", "username,host"]);
  assert.equal(rSid.status, 1, "user SID should still be flagged when only username/host disabled");
});

test("scan: --enable-all and --disable-categories together is a usage error", () => {
  const path = writeTempLog("x.log", "hello\n");
  const r = runCli(["scan", path, "--enable-all", "--disable-categories", "host"]);
  assert.equal(r.status, 2, asText(r.stderr) || asText(r.stdout));
  assert.match(asText(r.stderr), /not both/i);
});

test("scan: --profile and --disable-categories together is a usage error", () => {
  const path = writeTempLog("x.log", "hello\n");
  const r = runCli(["scan", path, "--profile", "generic", "--disable-categories", "host"]);
  assert.equal(r.status, 2, asText(r.stderr) || asText(r.stdout));
  assert.match(asText(r.stderr), /do not combine with --profile/i);
});

test("scan: unknown --disable-categories name is a usage error", () => {
  const path = writeTempLog("x.log", "hello\n");
  const r = runCli(["scan", path, "--disable-categories", "usernames"]);
  assert.equal(r.status, 2, asText(r.stderr) || asText(r.stdout));
  assert.match(asText(r.stderr), /unknown categor.*usernames/i);
  assert.match(asText(r.stderr), /known:/i);
});

test("redact: unknown --disable-categories name is a usage error", () => {
  const path = writeTempLog("x.log", "hello\n");
  const r = runCli(["redact", path, "-o", "-", "--disable-categories", "hosts"]);
  assert.equal(r.status, 2, asText(r.stderr) || asText(r.stdout));
  assert.match(asText(r.stderr), /unknown categor.*hosts/i);
});
