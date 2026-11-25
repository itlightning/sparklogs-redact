#!/usr/bin/env node

/**
 * CI gate: no known security advisory applies to any dependency in package-lock.json, shipped or
 * development, at any severity, unless advisory-ignore.json records why it does not.
 *
 * Runs `npm audit` over the lockfile at the repository root with AUDIT_ARGS, which fix the scope
 * so that npm settings from the environment or an .npmrc (omit, NODE_ENV=production, offline,
 * registry, workspace selection) cannot narrow it. Fails when an advisory has no ignore entry,
 * when an entry matches no current advisory (stale), when an entry has no reason, when the report
 * covers fewer packages than the lockfile lists, or when npm's output cannot be read.
 *
 * advisory-ignore.json maps each GHSA advisory id to its reason: { "GHSA-xxxx-xxxx-xxxx": "..." }.
 * The reason states why the advisory does not apply (not reachable, and why) or why no fix is
 * tolerable yet. An advisory that an upgrade can clear is upgraded, not ignored.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const IGNORE_FILE = "advisory-ignore.json";
const GHSA_ID = /^GHSA(-[0-9a-z]{4}){3}$/;
const GHSA_URL = /^https:\/\/github\.com\/advisories\/(GHSA(?:-[0-9a-z]{4}){3})$/;

// Each flag overrides a setting that would otherwise shrink the audit while still printing a
// clean report: omit / only / production / NODE_ENV (dependency types), offline (no advisory
// lookup at all), registry (an endpoint that returns no advisories), workspaces=false and
// workspace=<name> (part of the tree). The workspace folders are appended by auditArgs().
export const AUDIT_ARGS = [
  "audit",
  "--json",
  "--package-lock-only",
  "--include=dev",
  "--include=optional",
  "--include=peer",
  "--offline=false",
  "--registry=https://registry.npmjs.org/",
  "--workspaces=true",
  "--include-workspace-root=true",
];

/**
 * Full npm argument list: AUDIT_ARGS plus one --workspace per folder of the root package.json
 * `workspaces` globs. A --workspace on the command line replaces any workspace filter set in the
 * environment or an .npmrc.
 */
export function auditArgs(rootManifest) {
  const globs = rootManifest.workspaces ?? [];
  const folders = globs.map((glob) => {
    const folder = /^([^*]+)\/\*$/.exec(glob)?.[1];
    if (!folder) throw new Error(`package.json: workspace glob ${glob} is not of the form <dir>/*`);
    return `--workspace=${folder}`;
  });
  return [...AUDIT_ARGS, ...folders];
}

/** Validates the parsed ignore file; returns { id, reason } entries or lists every problem. */
export function parseIgnores(data) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`${IGNORE_FILE}: expected an object mapping advisory ids to reasons`);
  }
  const problems = [];
  for (const [id, reason] of Object.entries(data)) {
    if (!GHSA_ID.test(id)) problems.push(`${IGNORE_FILE}: ${JSON.stringify(id)} is not a GHSA id`);
    if (typeof reason !== "string" || reason.trim() === "") {
      problems.push(`${IGNORE_FILE}: ${id}: reason is required`);
    }
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
  return Object.entries(data).map(([id, reason]) => ({ id, reason }));
}

/**
 * Collects the advisories in an `npm audit --json` report (format 2), keyed by GHSA id. Throws when
 * the report is an error, has an unexpected shape, or counts vulnerabilities it does not list.
 */
export function collectAdvisories(report) {
  if (report?.error) {
    const why = report.error.summary || report.message || JSON.stringify(report.error);
    throw new Error(`npm audit failed: ${why}`);
  }
  if (report?.auditReportVersion !== 2 || typeof report.vulnerabilities !== "object") {
    throw new Error("npm audit: unexpected report format (need auditReportVersion 2)");
  }
  const advisories = new Map();
  for (const vuln of Object.values(report.vulnerabilities)) {
    for (const via of vuln.via ?? []) {
      if (typeof via !== "object") continue; // a package name: the advisory is listed under it
      const id = GHSA_URL.exec(via.url ?? "")?.[1];
      if (!id) {
        throw new Error(`npm audit: advisory for ${via.name} has no GHSA url: ${via.url}`);
      }
      const known = advisories.get(id) ?? {
        id,
        title: via.title,
        severity: via.severity,
        packages: [],
      };
      known.packages.push(`${via.name}@${via.range}`);
      advisories.set(id, known);
    }
  }
  const total = report.metadata?.vulnerabilities?.total;
  if (typeof total !== "number") {
    throw new Error("npm audit: report has no metadata.vulnerabilities.total");
  }
  if (total > 0 && advisories.size === 0) {
    throw new Error(`npm audit: report counts ${total} vulnerable packages but lists no advisory`);
  }
  return advisories;
}

/**
 * Returns how many packages the report covered. Throws when that is fewer than the lockfile's
 * installed (non-root, non-link) entries: the report then did not come from this lockfile.
 */
export function checkCoverage(report, lockfile) {
  const covered = report.metadata?.dependencies?.total;
  const listed = Object.entries(lockfile.packages ?? {}).filter(
    ([path, entry]) => path !== "" && !entry.link,
  ).length;
  if (typeof covered !== "number" || covered < listed) {
    throw new Error(`npm audit: report covers ${covered} packages, lockfile lists ${listed}`);
  }
  return covered;
}

/** Returns the gate's failure lines (empty when the gate passes). */
export function evaluate(advisories, ignores) {
  const failures = [];
  const ignored = new Set(ignores.map((e) => e.id));
  for (const adv of advisories.values()) {
    if (!ignored.has(adv.id)) {
      failures.push(`${adv.id} (${adv.severity}) ${adv.packages.join(", ")}: ${adv.title}`);
    }
  }
  for (const entry of ignores) {
    if (!advisories.has(entry.id)) {
      failures.push(`${entry.id}: ignore entry matches no current advisory; remove it`);
    }
  }
  return failures;
}

/** Runs npm audit in `root` through `exec` (execFileSync's signature) and parses its report. */
export function runAudit(root, args, exec = execFileSync) {
  let out;
  try {
    out = exec("npm", args, {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "inherit"],
    });
  } catch (err) {
    // npm audit exits non-zero when it finds advisories; the JSON report is still on stdout.
    if (typeof err.stdout !== "string" || err.stdout.trim() === "") throw err;
    out = err.stdout;
  }
  return parseJson(out, "npm audit output");
}

function parseJson(text, source) {
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${source}: not valid JSON: ${err.message}`);
  }
}

function readJson(name) {
  return parseJson(readFileSync(join(ROOT, name), "utf8"), name);
}

function main() {
  const fail = (lines) => {
    for (const line of lines) console.error(`FAIL: ${line}`);
    process.exit(1);
  };
  try {
    const ignores = parseIgnores(readJson(IGNORE_FILE));
    const report = runAudit(ROOT, auditArgs(readJson("package.json")));
    const advisories = collectAdvisories(report);
    const covered = checkCoverage(report, readJson("package-lock.json"));
    const failures = evaluate(advisories, ignores);
    if (failures.length > 0) fail(failures);
    console.log(
      `  ok: no unignored advisory across ${covered} packages ` +
        `(${advisories.size} advisories, ${ignores.length} ignored)`,
    );
  } catch (err) {
    fail(String(err.message).split("\n"));
  }
}

if (import.meta.main) main();
