#!/usr/bin/env node

/**
 * CI gate: no known security advisory applies to any npm dependency in the repository, shipped or
 * development, at any severity, unless advisory-ignore.json records why it does not.
 *
 * Inputs are found from the files git tracks: every package-lock.json is audited with `npm audit`
 * in its folder, with AUDIT_ARGS fixing the scope so that npm settings from the environment or an
 * .npmrc (omit, NODE_ENV=production, offline, registry, workspace selection) cannot narrow it.
 * Every tracked package.json needs a lockfile beside it or must be a workspace member of one.
 *
 * A dependency that does not come from the npm registry (git, tarball, file: or a link outside the
 * workspace folders) fails unless advisory-sources.json declares the registry package it copies;
 * the gate then asks OSV for advisories against that upstream release and treats them as findings.
 *
 * Fails closed: when npm or OSV cannot be reached or answers with something unreadable, when the
 * advisory endpoint does not return the advisory of a known-vulnerable control package, when a
 * report covers fewer packages than its lockfile lists, and when a lockfile has no packages map.
 *
 * advisory-ignore.json maps each advisory id to { "reason": "...", "until": "YYYY-MM-DD" }. The
 * reason states why the advisory does not apply (not reachable, and why) or why no fix is
 * tolerable yet. An entry lapses on its `until` date (UTC), which may be at most 90 days ahead.
 * An advisory that an upgrade can clear is upgraded, not ignored.
 *
 * `--github-output <file>` appends `finding_ids=<ids>` to that file: the advisories that failed the
 * gate, separated by spaces, empty when the gate passed or failed for another reason.
 */

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const IGNORE_FILE = "advisory-ignore.json";
export const SOURCES_FILE = "advisory-sources.json";
const LOCKFILE = "package-lock.json";
const MANIFEST = "package.json";
// Lockfiles of other package managers: this gate cannot audit them, so a tracked one fails.
const UNSUPPORTED_LOCKFILES = new Set([
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
]);
const REGISTRY = "https://registry.npmjs.org/";
const GHSA_ID = /^GHSA(-[0-9a-z]{4}){3}$/;
const GHSA_URL = /^https:\/\/github\.com\/advisories\/(GHSA(?:-[0-9a-z]{4}){3})$/;
// An ignore entry names exactly one advisory: a GitHub advisory or an OSV malicious-package id.
const ADVISORY_ID = /^(GHSA(-[0-9a-z]{4}){3}|MAL-\d{4}-\d+)$/;
const MAX_IGNORE_DAYS = 90;
const FETCH_TIMEOUT_MS = 30_000;

// PROVENANCE: OBSERVED registry.npmjs.org 2026-11-25, response trimmed in audit-gate.test.mjs.
// The bulk advisory endpoint npm audit queries; body { "<name>": ["<version>"] }, answer
// { "<name>": [{ "url": "https://github.com/advisories/GHSA-..." }] }.
export const NPM_ADVISORY_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";
// PROVENANCE: DOCUMENTED https://google.github.io/osv.dev/post-v1-query/ (checked 2026-11-25).
// Body { package: { name, ecosystem }, version, page_token? }, answer { vulns?, next_page_token? }.
export const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
// A release with a long-published advisory. Both endpoints must return it, or an empty answer
// from them proves nothing.
export const CONTROL = { name: "lodash", version: "4.17.20", id: "GHSA-35jh-r3h4-6jhm" };

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
  `--registry=${REGISTRY}`,
  "--workspaces=true",
  "--include-workspace-root=true",
];
const WORKSPACE_ARGS = new Set(["--workspaces=true", "--include-workspace-root=true"]);

/** Folders named by the manifest's `workspaces` globs, which must each be of the form <dir>/*. */
export function workspaceFolders(manifest) {
  return (manifest.workspaces ?? []).map((glob) => {
    const folder = /^([^*]+)\/\*$/.exec(glob)?.[1];
    if (!folder) throw new Error(`package.json: workspace glob ${glob} is not of the form <dir>/*`);
    return folder;
  });
}

/**
 * Full npm argument list: AUDIT_ARGS plus one --workspace per folder of the manifest's
 * `workspaces` globs. A --workspace on the command line replaces any workspace filter set in the
 * environment or an .npmrc. A project without workspaces drops the workspace flags, which npm
 * refuses there.
 */
export function auditArgs(manifest) {
  const folders = workspaceFolders(manifest);
  if (folders.length === 0) return AUDIT_ARGS.filter((a) => !WORKSPACE_ARGS.has(a));
  return [...AUDIT_ARGS, ...folders.map((f) => `--workspace=${f}`)];
}

/** Today's date in UTC as YYYY-MM-DD. */
export function utcDay(now) {
  return now.toISOString().slice(0, 10);
}

function addDays(day, days) {
  const date = new Date(`${day}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return utcDay(date);
}

function isDay(text) {
  if (typeof text !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(text)) return false;
  const date = new Date(`${text}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && utcDay(date) === text;
}

/**
 * Validates the parsed ignore file against `today` (YYYY-MM-DD, UTC); returns { id, reason, until }
 * entries or lists every problem. An entry lapses on its `until` date.
 */
export function parseIgnores(data, today) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`${IGNORE_FILE}: expected an object mapping advisory ids to entries`);
  }
  const latest = addDays(today, MAX_IGNORE_DAYS);
  const problems = [];
  for (const [id, entry] of Object.entries(data)) {
    const at = `${IGNORE_FILE}: ${id}`;
    if (!ADVISORY_ID.test(id)) problems.push(`${at}: not a single advisory id (GHSA or MAL)`);
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      problems.push(`${at}: expected { "reason": "...", "until": "YYYY-MM-DD" }`);
      continue;
    }
    if (typeof entry.reason !== "string" || entry.reason.trim() === "") {
      problems.push(`${at}: reason is required`);
    }
    if (!isDay(entry.until)) {
      problems.push(`${at}: until must be a date YYYY-MM-DD, got ${JSON.stringify(entry.until)}`);
    } else if (entry.until <= today) {
      problems.push(`${at}: lapsed on ${entry.until}; fix the advisory or review the entry`);
    } else if (entry.until > latest) {
      problems.push(`${at}: until ${entry.until} is more than ${MAX_IGNORE_DAYS} days ahead`);
    }
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
  return Object.entries(data).map(([id, e]) => ({ id, reason: e.reason, until: e.until }));
}

const DECLARATION_FIELDS = ["ecosystem", "upstream", "version", "why"];
const OPTIONAL_DECLARATION_FIELDS = ["commit"];

/**
 * Validates the parsed sources file; returns { name, upstream, version, ... } entries or lists
 * every problem. `version` is the newest upstream release the copy fully contains; `commit`, when
 * present, records the upstream commit it is based on.
 */
export function parseDeclarations(data) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`${SOURCES_FILE}: expected an object mapping package names to entries`);
  }
  const problems = [];
  for (const [name, entry] of Object.entries(data)) {
    const at = `${SOURCES_FILE}: ${name}`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      problems.push(`${at}: expected an object with ${DECLARATION_FIELDS.join(", ")}`);
      continue;
    }
    for (const field of DECLARATION_FIELDS) {
      if (typeof entry[field] !== "string" || entry[field].trim() === "") {
        problems.push(`${at}: ${field} is required`);
      }
    }
    for (const field of OPTIONAL_DECLARATION_FIELDS) {
      if (field in entry && (typeof entry[field] !== "string" || entry[field].trim() === "")) {
        problems.push(`${at}: ${field}, when present, must be a non-empty string`);
      }
    }
    for (const field of Object.keys(entry)) {
      if (!DECLARATION_FIELDS.includes(field) && !OPTIONAL_DECLARATION_FIELDS.includes(field)) {
        problems.push(`${at}: unknown field ${field}`);
      }
    }
    if (typeof entry.ecosystem === "string" && entry.ecosystem !== "npm") {
      problems.push(`${at}: ecosystem ${entry.ecosystem} is not read by this gate (npm only)`);
    }
  }
  if (problems.length > 0) throw new Error(problems.join("\n"));
  return Object.entries(data).map(([name, entry]) => ({ name, ...entry }));
}

/**
 * Sorts tracked paths into lockfile folders and manifest folders (posix, "." for the root), and
 * lists the problems discovery alone can prove.
 */
export function discover(tracked) {
  const lockDirs = [];
  const manifestDirs = [];
  const problems = [];
  for (const path of tracked) {
    const base = posix.basename(path);
    if (base === LOCKFILE) lockDirs.push(posix.dirname(path));
    else if (base === MANIFEST) manifestDirs.push(posix.dirname(path));
    else if (UNSUPPORTED_LOCKFILES.has(base)) {
      problems.push(`${path}: lockfile kind not audited by this gate; use ${LOCKFILE}`);
    }
  }
  for (const dir of lockDirs) {
    if (!manifestDirs.includes(dir)) problems.push(`${posix.join(dir, LOCKFILE)}: no ${MANIFEST}`);
  }
  return { lockDirs, manifestDirs, problems };
}

/**
 * Lists manifests that no lockfile covers: a manifest is covered by a lockfile in its own folder
 * or by an ancestor lockfile that records its folder as a package. `lockfiles` maps folder to
 * lockfile.
 */
export function uncoveredManifests(manifestDirs, lockfiles) {
  const problems = [];
  for (const dir of manifestDirs) {
    if (lockfiles.has(dir)) continue;
    const covered = [...lockfiles].some(([lockDir, lockfile]) => {
      const rel = posix.relative(lockDir, dir);
      return !rel.startsWith("..") && Object.hasOwn(lockfile.packages, rel);
    });
    if (!covered) problems.push(`${posix.join(dir, MANIFEST)}: no ${LOCKFILE} covers it`);
  }
  return problems;
}

/**
 * Returns the lockfile's dependencies that do not come from the npm registry, as
 * { name, source }. A workspace member of this lockfile's project is first-party and skipped.
 * Throws on a lockfile without a packages map (lockfileVersion 1), which npm audit and this check
 * would otherwise pass without reading.
 */
export function nonRegistryDependencies(lockfile, manifest, where) {
  if (!(lockfile?.lockfileVersion >= 2) || typeof lockfile.packages !== "object") {
    throw new Error(
      `${where}: lockfileVersion ${lockfile?.lockfileVersion} has no packages map; ` +
        "regenerate it with npm 7 or later",
    );
  }
  const folders = workspaceFolders(manifest);
  const isMember = (target) =>
    typeof target === "string" &&
    !target.split("/").includes("..") &&
    folders.includes(posix.dirname(target));
  const found = [];
  for (const [key, entry] of Object.entries(lockfile.packages)) {
    const at = key.lastIndexOf("node_modules/");
    // The project root and package folders: a link entry under node_modules points at each.
    if (at < 0) continue;
    const name = key.slice(at + "node_modules/".length);
    if (entry.link) {
      if (!isMember(entry.resolved)) found.push({ name, source: `link to ${entry.resolved}` });
    } else if (typeof entry.resolved === "string") {
      if (!entry.resolved.startsWith(REGISTRY)) found.push({ name, source: entry.resolved });
    } else if (!entry.inBundle) {
      // A bundled package ships inside its parent's tarball, which is checked on its own.
      found.push({ name, source: "no resolved source" });
    }
  }
  return found;
}

/** Failure lines for undeclared non-registry dependencies and for stale declarations. */
export function checkDeclarations(declarations, dependencies) {
  const failures = [];
  const declared = new Set(declarations.map((d) => d.name));
  const seen = new Set();
  for (const dep of dependencies) {
    seen.add(dep.name);
    if (!declared.has(dep.name)) {
      failures.push(
        `${dep.name} (${dep.source}) does not come from the npm registry; ` +
          `declare its upstream in ${SOURCES_FILE}`,
      );
    }
  }
  for (const decl of declarations) {
    if (!seen.has(decl.name)) {
      failures.push(`${SOURCES_FILE}: ${decl.name} matches no non-registry dependency; remove it`);
    }
  }
  return failures;
}

async function postJson(url, body, fetchFn) {
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const data = parseJson(await res.text(), url);
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`${url}: expected a JSON object`);
  }
  return data;
}

/** OSV advisories for an npm package at a version, as [{ id, summary, severity }]. */
export async function queryOsv(name, version, fetchFn) {
  const vulns = [];
  let pageToken;
  do {
    const body = { package: { name, ecosystem: "npm" }, version };
    if (pageToken) body.page_token = pageToken;
    const data = await postJson(OSV_QUERY_URL, body, fetchFn);
    const page = data.vulns ?? [];
    if (!Array.isArray(page)) throw new Error(`${OSV_QUERY_URL}: vulns is not a list`);
    for (const v of page) {
      if (typeof v?.id !== "string") throw new Error(`${OSV_QUERY_URL}: advisory without an id`);
      vulns.push({ id: v.id, summary: v.summary, severity: v.database_specific?.severity });
    }
    pageToken = data.next_page_token;
  } while (pageToken);
  return vulns;
}

/** Throws unless the npm advisory endpoint returns the control package's advisory. */
export async function checkNpmEndpoint(fetchFn) {
  const data = await postJson(NPM_ADVISORY_URL, { [CONTROL.name]: [CONTROL.version] }, fetchFn);
  const ids = (data[CONTROL.name] ?? []).map((a) => GHSA_URL.exec(a?.url ?? "")?.[1]);
  if (!ids.includes(CONTROL.id)) {
    throw new Error(
      `${NPM_ADVISORY_URL}: no ${CONTROL.id} for ${CONTROL.name}@${CONTROL.version}; ` +
        "the advisory endpoint is not answering",
    );
  }
}

/** Throws unless OSV returns the control package's advisory. */
export async function checkOsvEndpoint(fetchFn) {
  const vulns = await queryOsv(CONTROL.name, CONTROL.version, fetchFn);
  if (!vulns.some((v) => v.id === CONTROL.id)) {
    throw new Error(
      `${OSV_QUERY_URL}: no ${CONTROL.id} for ${CONTROL.name}@${CONTROL.version}; ` +
        "OSV is not answering",
    );
  }
}

/** Adds OSV advisories for each declared upstream release to `findings`. */
export async function collectDeclaredAdvisories(declarations, findings, fetchFn) {
  for (const decl of declarations) {
    for (const v of await queryOsv(decl.upstream, decl.version, fetchFn)) {
      addFinding(findings, {
        id: v.id,
        title: v.summary ?? "(no summary)",
        severity: (v.severity ?? "unrated").toLowerCase(),
        pkg: `${decl.name} (copy of ${decl.upstream}@${decl.version})`,
      });
    }
  }
}

function addFinding(findings, { id, title, severity, pkg }) {
  const known = findings.get(id) ?? { id, title, severity, packages: [] };
  known.packages.push(pkg);
  findings.set(id, known);
}

/**
 * Adds the advisories in an `npm audit --json` report (format 2) to `findings`, keyed by GHSA id.
 * Throws when the report is an error, has an unexpected shape, or counts vulnerabilities it does
 * not list.
 */
export function collectAdvisories(report, findings = new Map()) {
  if (report?.error) {
    const why = report.error.summary || report.message || JSON.stringify(report.error);
    throw new Error(`npm audit failed: ${why}`);
  }
  if (report?.auditReportVersion !== 2 || typeof report.vulnerabilities !== "object") {
    throw new Error("npm audit: unexpected report format (need auditReportVersion 2)");
  }
  let listed = 0;
  for (const vuln of Object.values(report.vulnerabilities)) {
    for (const via of vuln.via ?? []) {
      if (typeof via !== "object") continue; // a package name: the advisory is listed under it
      const id = GHSA_URL.exec(via.url ?? "")?.[1];
      if (!id) {
        throw new Error(`npm audit: advisory for ${via.name} has no GHSA url: ${via.url}`);
      }
      const { title, severity } = via;
      addFinding(findings, { id, title, severity, pkg: `${via.name}@${via.range}` });
      listed += 1;
    }
  }
  const total = report.metadata?.vulnerabilities?.total;
  if (typeof total !== "number") {
    throw new Error("npm audit: report has no metadata.vulnerabilities.total");
  }
  if (total > 0 && listed === 0) {
    throw new Error(`npm audit: report counts ${total} vulnerable packages but lists no advisory`);
  }
  return findings;
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

/** Returns { failures, findingIds }: findingIds are the advisories with no ignore entry. */
export function evaluate(findings, ignores) {
  const failures = [];
  const findingIds = [];
  const ignored = new Set(ignores.map((e) => e.id));
  for (const adv of findings.values()) {
    if (!ignored.has(adv.id)) {
      findingIds.push(adv.id);
      failures.push(`${adv.id} (${adv.severity}) ${adv.packages.join(", ")}: ${adv.title}`);
    }
  }
  for (const entry of ignores) {
    if (!findings.has(entry.id)) {
      failures.push(`${entry.id}: ignore entry matches no current advisory; remove it`);
    }
  }
  return { failures, findingIds };
}

/** Runs npm audit in `cwd` through `exec` (execFileSync's signature) and parses its report. */
export function runAudit(cwd, args, exec = execFileSync) {
  let out;
  try {
    out = exec("npm", args, {
      cwd,
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

/** Appends `finding_ids=<ids>` to a GitHub Actions output file. */
export function writeFindingIds(file, ids, append = appendFileSync) {
  append(file, `finding_ids=${ids.join(" ")}\n`);
}

function parseJson(text, source) {
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${source}: not valid JSON: ${err.message}`);
  }
}

function readJson(path) {
  return parseJson(readFileSync(join(ROOT, path), "utf8"), path);
}

function trackedFiles() {
  const out = execFileSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf8" });
  return out.split("\0").filter(Boolean);
}

async function run() {
  const ignores = parseIgnores(readJson(IGNORE_FILE), utcDay(new Date()));
  const declarations = parseDeclarations(readJson(SOURCES_FILE));
  const { lockDirs, manifestDirs, problems } = discover(trackedFiles());
  const failures = [...problems];
  const projects = lockDirs.map((dir) => ({
    dir,
    lockfile: readJson(posix.join(dir, LOCKFILE)),
    manifest: readJson(posix.join(dir, MANIFEST)),
  }));
  const dependencies = projects.flatMap(({ dir, lockfile, manifest }) =>
    nonRegistryDependencies(lockfile, manifest, posix.join(dir, LOCKFILE)),
  );
  const lockfiles = new Map(projects.map(({ dir, lockfile }) => [dir, lockfile]));
  failures.push(...uncoveredManifests(manifestDirs, lockfiles));

  await checkNpmEndpoint(fetch);
  const findings = new Map();
  let covered = 0;
  for (const { dir, lockfile, manifest } of projects) {
    const report = runAudit(join(ROOT, dir), auditArgs(manifest));
    collectAdvisories(report, findings);
    covered += checkCoverage(report, lockfile);
  }
  failures.push(...checkDeclarations(declarations, dependencies));
  if (declarations.length > 0) {
    await checkOsvEndpoint(fetch);
    await collectDeclaredAdvisories(declarations, findings, fetch);
  }
  const result = evaluate(findings, ignores);
  failures.push(...result.failures);
  const summary =
    `${covered} packages in ${lockfiles.size} lockfile(s), ${declarations.length} declared ` +
    `source(s), ${findings.size} advisories, ${ignores.length} ignored`;
  return { failures, findingIds: result.findingIds, summary };
}

async function main() {
  const flag = process.argv.indexOf("--github-output");
  const outputFile = flag >= 0 ? process.argv[flag + 1] : undefined;
  if (flag >= 0 && !outputFile) {
    console.error("FAIL: --github-output needs a file");
    process.exit(1);
  }
  let failures;
  let findingIds = [];
  let summary;
  try {
    ({ failures, findingIds, summary } = await run());
  } catch (err) {
    // fetch reports a network failure as "fetch failed" with the reason in `cause`.
    const cause = err.cause ? `: ${err.cause.message ?? err.cause}` : "";
    failures = `${err.message}${cause}`.split("\n");
  }
  if (outputFile) writeFindingIds(outputFile, findingIds);
  for (const line of failures) console.error(`FAIL: ${line}`);
  if (failures.length > 0) process.exit(1);
  console.log(`  ok: no unignored advisory across ${summary}`);
}

if (import.meta.main) await main();
