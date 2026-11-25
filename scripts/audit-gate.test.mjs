import { test } from "node:test";
import assert from "node:assert/strict";
import {
  auditArgs,
  checkCoverage,
  collectAdvisories,
  evaluate,
  parseIgnores,
  runAudit,
} from "./audit-gate.mjs";

// Trimmed from a real `npm audit --json` report: vitest lists its own advisory plus a transitive
// one by package name, which is reported again under @vitest/mocker.
function report() {
  return {
    auditReportVersion: 2,
    vulnerabilities: {
      vitest: {
        name: "vitest",
        severity: "moderate",
        via: [
          "@vitest/mocker",
          {
            source: 1193683,
            name: "vitest",
            title: "Vitest: Path Traversal / Arbitrary File Read via @vitest/mocker Redirect Mock",
            url: "https://github.com/advisories/GHSA-82fw-gwwq-j7x9",
            severity: "moderate",
            range: ">=2.1.0 <4.1.11",
          },
        ],
      },
      "@vitest/mocker": {
        name: "@vitest/mocker",
        severity: "moderate",
        via: [
          {
            source: 1193684,
            name: "@vitest/mocker",
            title: "Vitest: Code injection via unauthenticated manual mock registration",
            url: "https://github.com/advisories/GHSA-qxg6-89mg-rqv8",
            severity: "moderate",
            range: "<=4.1.11",
          },
        ],
      },
    },
    metadata: { vulnerabilities: { low: 0, moderate: 2, high: 0, critical: 0, total: 2 } },
  };
}

const CLEAN = {
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: { vulnerabilities: { total: 0 } },
};

test("a clean report with an empty ignore file passes", () => {
  assert.deepEqual(evaluate(collectAdvisories(CLEAN), []), []);
});

test("every advisory without an ignore entry fails, whatever its severity", () => {
  const low = report();
  low.vulnerabilities.vitest.via[1].severity = "low";
  const failures = evaluate(collectAdvisories(low), []);
  assert.equal(failures.length, 2);
  assert.match(failures[0], /^GHSA-82fw-gwwq-j7x9 \(low\) vitest@>=2\.1\.0 <4\.1\.11: /);
  assert.match(failures[1], /^GHSA-qxg6-89mg-rqv8 /);
});

test("an ignore entry clears only its own advisory", () => {
  const ignores = parseIgnores({ "GHSA-82fw-gwwq-j7x9": "test reason" });
  const failures = evaluate(collectAdvisories(report()), ignores);
  assert.deepEqual(failures.length, 1);
  assert.match(failures[0], /^GHSA-qxg6-89mg-rqv8 /);
});

test("an ignore entry that matches no advisory fails as stale", () => {
  const ignores = parseIgnores({ "GHSA-82fw-gwwq-j7x9": "test reason" });
  assert.deepEqual(evaluate(collectAdvisories(CLEAN), ignores), [
    "GHSA-82fw-gwwq-j7x9: ignore entry matches no current advisory; remove it",
  ]);
});

test("ignore entries need a GHSA id and a non-empty reason", () => {
  const bad = [
    { "GHSA-82fw-gwwq-j7x9": "" },
    { "GHSA-82fw-gwwq-j7x9": "  " },
    { "GHSA-82fw-gwwq-j7x9": null },
    { "GHSA-82fw-gwwq-j7x9": { reason: "r" } },
    { "CVE-2026-0001": "r" },
    [],
    null,
  ];
  for (const data of bad) {
    assert.throws(() => parseIgnores(data), /advisory-ignore\.json/, JSON.stringify(data));
  }
  assert.deepEqual(parseIgnores({}), []);
});

test("an audit that cannot run or cannot be read fails closed", () => {
  assert.throws(() => collectAdvisories({ error: { summary: "network down" } }), /network down/);
  const emptySummary = { message: "audit endpoint returned an error", error: { summary: "" } };
  assert.throws(() => collectAdvisories(emptySummary), /audit endpoint returned an error/);
  const noTotal = { auditReportVersion: 2, vulnerabilities: {}, metadata: {} };
  assert.throws(() => collectAdvisories(noTotal), /no metadata\.vulnerabilities\.total/);
  assert.throws(() => collectAdvisories({ auditReportVersion: 1, advisories: {} }), /format/);
  const unlisted = { ...CLEAN, metadata: { vulnerabilities: { total: 3 } } };
  assert.throws(() => collectAdvisories(unlisted), /lists no advisory/);
  const noUrl = report();
  delete noUrl.vulnerabilities.vitest.via[1].url;
  assert.throws(() => collectAdvisories(noUrl), /no GHSA url/);
});

test("a report covering fewer packages than the lockfile lists fails", () => {
  const lockfile = {
    packages: {
      "": { name: "root" },
      "node_modules/a": { version: "1.0.0" },
      "node_modules/b": { version: "1.0.0" },
      "node_modules/@scope/ws": { link: true, resolved: "packages/ws" },
      "packages/ws": { version: "0.1.0" },
    },
  };
  const covering = (total) => ({ metadata: { dependencies: { total } } });
  assert.equal(checkCoverage(covering(4), lockfile), 4);
  assert.throws(() => checkCoverage(covering(2), lockfile), /covers 2 packages, lockfile lists 3/);
  assert.throws(() => checkCoverage({ metadata: {} }, lockfile), /covers undefined packages/);
});

test("workspace globs become --workspace folders; other glob shapes are refused", () => {
  const args = auditArgs({ workspaces: ["packages/*", "tools/*"] });
  assert.deepEqual(args.slice(-2), ["--workspace=packages", "--workspace=tools"]);
  assert.throws(() => auditArgs({ workspaces: ["packages/**"] }), /not of the form <dir>\/\*/);
});

// Stands in for npm in an environment set to narrow the audit every way npm allows: each setting
// below applies unless the command line overrides it, and any narrowing yields a clean report.
function narrowingNpm(command, args, options) {
  assert.equal(command, "npm");
  assert.equal(options.cwd, "/repo");
  const flags = new Set(args);
  const narrowed = [
    !flags.has("--include=dev"), // NODE_ENV=production, omit=dev, only=prod, production=true
    !flags.has("--include=optional"), // omit=optional
    !flags.has("--include=peer"), // omit=peer
    !flags.has("--offline=false"), // offline=true: no advisory lookup, still a clean report
    !flags.has("--registry=https://registry.npmjs.org/"), // a registry with no advisories
    !flags.has("--workspaces=true"), // workspaces=false: root dependencies only
    !flags.has("--include-workspace-root=true"), // workspace filter without the root
    !args.some((a) => a.startsWith("--workspace=")), // workspace=<one package>
    !flags.has("--package-lock-only"),
    !flags.has("--json"),
  ].some(Boolean);
  const out = JSON.stringify(narrowed ? CLEAN : report());
  // npm audit exits 1 when it finds advisories, with the report on stdout.
  if (!narrowed) throw Object.assign(new Error("npm exited 1"), { stdout: out });
  return out;
}

test("the gate's npm arguments override every setting that narrows the audit", () => {
  const args = auditArgs({ workspaces: ["packages/*"] });
  const advisories = collectAdvisories(runAudit("/repo", args, narrowingNpm));
  assert.deepEqual([...advisories.keys()], ["GHSA-82fw-gwwq-j7x9", "GHSA-qxg6-89mg-rqv8"]);
  for (const dropped of args.slice(1)) {
    const fewer = args.filter((a) => a !== dropped);
    const narrowed = collectAdvisories(runAudit("/repo", fewer, narrowingNpm));
    assert.equal(narrowed.size, 0, `dropping ${dropped} should narrow the stand-in audit`);
  }
});

test("an npm failure with no report on stdout is rethrown", () => {
  const broken = () => {
    throw Object.assign(new Error("spawn npm ENOENT"), { stdout: "" });
  };
  assert.throws(() => runAudit("/repo", ["audit"], broken), /ENOENT/);
});
