import { test } from "node:test";
import assert from "node:assert/strict";
import { collectAdvisories, evaluate, parseIgnores } from "./audit-gate.mjs";

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
  assert.throws(() => collectAdvisories({ auditReportVersion: 1, advisories: {} }), /format/);
  const unlisted = { ...CLEAN, metadata: { vulnerabilities: { total: 3 } } };
  assert.throws(() => collectAdvisories(unlisted), /lists no advisory/);
  const noUrl = report();
  delete noUrl.vulnerabilities.vitest.via[1].url;
  assert.throws(() => collectAdvisories(noUrl), /no GHSA url/);
});
