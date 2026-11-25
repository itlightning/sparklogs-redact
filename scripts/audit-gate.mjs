#!/usr/bin/env node

/**
 * CI gate: no known security advisory applies to any dependency in package-lock.json, shipped or
 * development, at any severity, unless advisory-ignore.json records why it does not.
 *
 * Runs `npm audit --json --package-lock-only` in the current directory and reads
 * ./advisory-ignore.json there. Fails when an advisory has no entry, when an entry matches no
 * current advisory (stale), when an entry has no reason, or when the audit itself cannot run.
 *
 * advisory-ignore.json maps each GHSA advisory id to its reason: { "GHSA-xxxx-xxxx-xxxx": "..." }.
 * The reason states why the advisory does not apply (not reachable, and why) or why no fix is
 * tolerable yet. An advisory that an upgrade can clear is upgraded, not ignored.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const IGNORE_FILE = "advisory-ignore.json";
const GHSA_ID = /^GHSA(-[0-9a-z]{4}){3}$/;
const GHSA_URL = /^https:\/\/github\.com\/advisories\/(GHSA(?:-[0-9a-z]{4}){3})$/;

/** Validates the parsed ignore file; returns { id, reason } entries or lists every problem. */
export function parseIgnores(data) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`${IGNORE_FILE}: expected an object mapping advisory ids to reasons`);
  }
  const problems = [];
  for (const [id, reason] of Object.entries(data)) {
    if (!GHSA_ID.test(id)) problems.push(`${JSON.stringify(id)}: not a GHSA advisory id`);
    if (typeof reason !== "string" || reason.trim() === "") {
      problems.push(`${id}: reason is required`);
    }
  }
  if (problems.length > 0) {
    throw new Error(`${IGNORE_FILE}:\n  ${problems.join("\n  ")}`);
  }
  return Object.entries(data).map(([id, reason]) => ({ id, reason }));
}

/**
 * Collects the advisories in an `npm audit --json` report (format 2), keyed by GHSA id. Throws when
 * the report is an error, has an unexpected shape, or counts vulnerabilities it does not list.
 */
export function collectAdvisories(report) {
  if (report?.error) {
    throw new Error(`npm audit failed: ${report.error.summary || JSON.stringify(report.error)}`);
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

function runAudit(cwd) {
  try {
    return execFileSync("npm", ["audit", "--json", "--package-lock-only"], {
      cwd,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "inherit"],
    });
  } catch (err) {
    // npm audit exits non-zero when it finds advisories; the JSON report is still on stdout.
    if (typeof err.stdout === "string" && err.stdout.trim() !== "") return err.stdout;
    throw err;
  }
}

function parseJson(text, source) {
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${source}: not valid JSON: ${err.message}`);
  }
}

function main() {
  const cwd = process.cwd();
  try {
    const ignoreText = readFileSync(join(cwd, IGNORE_FILE), "utf8");
    const ignores = parseIgnores(parseJson(ignoreText, IGNORE_FILE));
    const advisories = collectAdvisories(parseJson(runAudit(cwd), "npm audit output"));
    const failures = evaluate(advisories, ignores);
    if (failures.length > 0) {
      console.error(`audit-gate: ${failures.length} problem(s):`);
      for (const line of failures) console.error(`  ${line}`);
      process.exit(1);
    }
    console.log(
      `  ok: no unignored advisory (${advisories.size} advisories, ${ignores.length} ignored)`,
    );
  } catch (err) {
    console.error(`audit-gate: ${err.message}`);
    process.exit(1);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
