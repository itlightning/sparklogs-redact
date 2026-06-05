#!/usr/bin/env node

/**
 * CI gate: @sparklogs/redact-* packages share one semver, core dep ranges match,
 * and every package CHANGELOG follows the lockstep release conventions.
 */

import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES = ["redact-core", "redact-cli", "redact-react"];
const RELEASE_HEADING = /^## (\d+\.\d+\.\d+)\s*$/m;
const UNRELEASED_HEADING = /^## Unreleased\s*$/m;

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function fail(message) {
  console.error(`check-lockstep-versions: ${message}`);
  process.exit(1);
}

function ok(message) {
  console.log(`  ok: ${message}`);
}

const versions = {};
for (const pkg of PACKAGES) {
  const pkgPath = join(ROOT, "packages", pkg, "package.json");
  versions[pkg] = readJson(pkgPath).version;
}

const unique = [...new Set(Object.values(versions))];
if (unique.length !== 1) {
  fail(`package.json versions differ: ${JSON.stringify(versions)}`);
}
const version = unique[0];
ok(`all package.json versions are ${version}`);

for (const pkg of ["redact-cli", "redact-react"]) {
  const data = readJson(join(ROOT, "packages", pkg, "package.json"));
  const coreDep = data.dependencies?.["@sparklogs/redact-core"];
  const expected = `^${version}`;
  if (coreDep !== expected) {
    fail(
      `${pkg} depends on @sparklogs/redact-core@${coreDep ?? "(missing)"}, expected ${expected}`,
    );
  }
  ok(`${pkg} depends on @sparklogs/redact-core@${coreDep}`);
}

function loadChangelog(pkg) {
  const path = join(ROOT, "packages", pkg, "CHANGELOG.md");
  if (!existsSync(path)) {
    fail(`missing ${path}`);
  }
  const content = readFileSync(path, "utf8");
  const hasUnreleased = UNRELEASED_HEADING.test(content);
  const releasedMatch = content.match(RELEASE_HEADING);
  const releasedVersion = releasedMatch?.[1] ?? null;
  const unreleasedIndex = content.search(UNRELEASED_HEADING);
  const releasedIndex = content.search(RELEASE_HEADING);
  return { pkg, content, hasUnreleased, releasedVersion, unreleasedIndex, releasedIndex };
}

const changelogs = PACKAGES.map(loadChangelog);

const unreleasedStates = changelogs.map((c) => c.hasUnreleased);
const allUnreleased = unreleasedStates.every(Boolean);
const noneUnreleased = unreleasedStates.every((v) => !v);
if (!allUnreleased && !noneUnreleased) {
  const detail = changelogs.map((c) => `${c.pkg}=${c.hasUnreleased ? "yes" : "no"}`).join(", ");
  fail(`## Unreleased must be present in all changelogs or in none (${detail})`);
}
ok(allUnreleased ? "all changelogs have ## Unreleased" : "no changelogs have ## Unreleased");

for (const c of changelogs) {
  if (!c.releasedVersion) {
    fail(`${c.pkg} CHANGELOG has no ## X.Y.Z release section`);
  }
  if (c.releasedVersion !== version) {
    fail(
      `${c.pkg} CHANGELOG latest release is ${c.releasedVersion}, expected ${version} (package.json)`,
    );
  }
  if (c.hasUnreleased && c.unreleasedIndex >= 0 && c.releasedIndex >= 0 && c.unreleasedIndex > c.releasedIndex) {
    fail(`${c.pkg} CHANGELOG: ## Unreleased must appear above ## ${c.releasedVersion}`);
  }
  ok(`${c.pkg} CHANGELOG release section is ## ${c.releasedVersion}`);
}

console.log("check-lockstep-versions: all checks passed");
