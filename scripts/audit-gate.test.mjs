import { test } from "node:test";
import assert from "node:assert/strict";
import {
  auditArgs,
  checkCoverage,
  checkDeclarations,
  checkNpmEndpoint,
  checkOsvEndpoint,
  collectAdvisories,
  collectDeclaredAdvisories,
  discover,
  evaluate,
  nonRegistryDependencies,
  NPM_ADVISORY_URL,
  OSV_QUERY_URL,
  parseDeclarations,
  parseIgnores,
  queryOsv,
  runAudit,
  uncoveredManifests,
  utcDay,
  writeFindingIds,
} from "./audit-gate.mjs";

const TODAY = "2026-11-25";
const entry = (until = "2027-01-01") => ({ reason: "test reason", until });

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
  assert.deepEqual(evaluate(collectAdvisories(CLEAN), []), { failures: [], findingIds: [] });
});

test("every advisory without an ignore entry fails, whatever its severity", () => {
  const low = report();
  low.vulnerabilities.vitest.via[1].severity = "low";
  const { failures, findingIds } = evaluate(collectAdvisories(low), []);
  assert.deepEqual(findingIds, ["GHSA-82fw-gwwq-j7x9", "GHSA-qxg6-89mg-rqv8"]);
  assert.equal(failures.length, 2);
  assert.match(failures[0], /^GHSA-82fw-gwwq-j7x9 \(low\) vitest@>=2\.1\.0 <4\.1\.11: /);
  assert.match(failures[1], /^GHSA-qxg6-89mg-rqv8 /);
});

test("an ignore entry clears only its own advisory", () => {
  const ignores = parseIgnores({ "GHSA-82fw-gwwq-j7x9": entry() }, TODAY);
  const { failures, findingIds } = evaluate(collectAdvisories(report()), ignores);
  assert.deepEqual(findingIds, ["GHSA-qxg6-89mg-rqv8"]);
  assert.deepEqual(failures.length, 1);
  assert.match(failures[0], /^GHSA-qxg6-89mg-rqv8 /);
});

test("an ignore entry that matches no advisory fails as stale", () => {
  const ignores = parseIgnores({ "GHSA-82fw-gwwq-j7x9": entry() }, TODAY);
  assert.deepEqual(evaluate(collectAdvisories(CLEAN), ignores), {
    failures: ["GHSA-82fw-gwwq-j7x9: ignore entry matches no current advisory; remove it"],
    findingIds: [],
  });
});

test("ignore entries name one advisory and carry a reason and an until date", () => {
  const bad = {
    "no reason": { "GHSA-82fw-gwwq-j7x9": { until: "2027-01-01" } },
    "blank reason": { "GHSA-82fw-gwwq-j7x9": { reason: "  ", until: "2027-01-01" } },
    "no until": { "GHSA-82fw-gwwq-j7x9": { reason: "r" } },
    "unparseable until": { "GHSA-82fw-gwwq-j7x9": entry("next spring") },
    "impossible date": { "GHSA-82fw-gwwq-j7x9": entry("2027-02-30") },
    "until not a string": { "GHSA-82fw-gwwq-j7x9": entry(20270101) },
    "reason only (old form)": { "GHSA-82fw-gwwq-j7x9": "r" },
    "a package": { vitest: entry() },
    "a severity": { high: entry() },
    "a wildcard": { "GHSA-*": entry() },
    "a CVE id": { "CVE-2026-0001": entry() },
    "a list": [],
    null: null,
  };
  for (const [label, data] of Object.entries(bad)) {
    assert.throws(() => parseIgnores(data, TODAY), /advisory-ignore\.json/, label);
  }
  assert.deepEqual(parseIgnores({}, TODAY), []);
  const extra = { reason: "r", until: "2027-01-01", reviewed: "2026-11-20" };
  assert.deepEqual(parseIgnores({ "MAL-2026-123": extra }, TODAY), [
    { id: "MAL-2026-123", reason: "r", until: "2027-01-01" },
  ]);
});

test("an ignore entry lapses on its until date and may reach 90 days ahead", () => {
  const at = (until, today) => () => parseIgnores({ "GHSA-82fw-gwwq-j7x9": entry(until) }, today);
  assert.doesNotThrow(at("2026-11-26", TODAY));
  assert.throws(at("2026-11-25", TODAY), /lapsed on 2026-11-25/);
  assert.throws(at("2026-11-01", TODAY), /lapsed on 2026-11-01/);
  assert.doesNotThrow(at("2027-02-23", TODAY)); // today + 90
  assert.throws(at("2027-02-24", TODAY), /more than 90 days ahead/); // today + 91
  // Across a leap day: 2028-01-01 + 90 days is 2028-03-31.
  assert.doesNotThrow(at("2028-03-31", "2028-01-01"));
  assert.throws(at("2028-04-01", "2028-01-01"), /more than 90 days/);
});

test("today is the UTC date, whatever the local offset", () => {
  assert.equal(utcDay(new Date("2026-11-25T23:30:00-05:00")), "2026-11-26");
  assert.equal(utcDay(new Date("2026-11-26T00:30:00+02:00")), "2026-11-25");
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

test("a project without workspaces drops the workspace flags, which npm refuses there", () => {
  const args = auditArgs({});
  assert.ok(!args.some((a) => a.startsWith("--workspace")));
  assert.ok(!args.includes("--include-workspace-root=true"));
  assert.ok(args.includes("--include=dev"));
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

test("discovery audits every tracked package-lock.json and refuses other lockfile kinds", () => {
  const { lockDirs, manifestDirs, problems } = discover([
    "package.json",
    "package-lock.json",
    "packages/a/package.json",
    "tools/x/package.json",
    "tools/x/package-lock.json",
    "site/yarn.lock",
    "orphan/package-lock.json",
    "README.md",
  ]);
  assert.deepEqual(lockDirs, [".", "tools/x", "orphan"]);
  assert.deepEqual(manifestDirs, [".", "packages/a", "tools/x"]);
  assert.deepEqual(problems, [
    "site/yarn.lock: lockfile kind not audited by this gate; use package-lock.json",
    "orphan/package-lock.json: no package.json",
  ]);
});

test("a manifest needs its own lockfile or a workspace entry in an ancestor lockfile", () => {
  const lockfiles = new Map([
    [".", { packages: { "": {}, "packages/a": { version: "1.0.0" } } }],
    ["tools/x", { packages: { "": {} } }],
  ]);
  const dirs = [".", "packages/a", "tools/x", "packages/b", "demo"];
  assert.deepEqual(uncoveredManifests(dirs, lockfiles), [
    "packages/b/package.json: no package-lock.json covers it",
    "demo/package.json: no package-lock.json covers it",
  ]);
});

const MANIFEST = { workspaces: ["packages/*"] };
const reg = (name, version = "1.0.0") => ({
  version,
  resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
});

test("only registry packages and links to workspace members need no declaration", () => {
  const lockfile = {
    lockfileVersion: 3,
    packages: {
      "": { name: "root" },
      "packages/core": { version: "0.4.0" },
      "node_modules/@scope/core": { link: true, resolved: "packages/core" },
      "node_modules/lodash": reg("lodash"),
      "packages/core/node_modules/nested": reg("nested"),
      "node_modules/bundled": { version: "1.0.0", inBundle: true },
      "node_modules/forked": { resolved: "git+ssh://git@github.com/someone/forked.git#abc" },
      "node_modules/tarball": { resolved: "https://example.com/tarball-1.0.0.tgz" },
      "node_modules/local-tgz": { resolved: "file:vendor/local-tgz-1.0.0.tgz" },
      "node_modules/outside": { link: true, resolved: "../elsewhere/outside" },
      "node_modules/vendored": { link: true, resolved: "vendor/vendored" },
      "node_modules/escape": { link: true, resolved: "packages/../../escape" },
      "packages/core/node_modules/unresolved": { version: "1.0.0" },
    },
  };
  assert.deepEqual(nonRegistryDependencies(lockfile, MANIFEST, "package-lock.json"), [
    { name: "forked", source: "git+ssh://git@github.com/someone/forked.git#abc" },
    { name: "tarball", source: "https://example.com/tarball-1.0.0.tgz" },
    { name: "local-tgz", source: "file:vendor/local-tgz-1.0.0.tgz" },
    { name: "outside", source: "link to ../elsewhere/outside" },
    { name: "vendored", source: "link to vendor/vendored" },
    { name: "escape", source: "link to packages/../../escape" },
    { name: "unresolved", source: "no resolved source" },
  ]);
});

test("a lockfile without a packages map is refused, not passed", () => {
  const v1 = { lockfileVersion: 1, dependencies: { lodash: { version: "4.17.20" } } };
  const read = (lockfile) => () => nonRegistryDependencies(lockfile, MANIFEST, "package-lock.json");
  assert.throws(read(v1), /lockfileVersion 1/);
  assert.throws(read({ lockfileVersion: 3 }), /no packages map/);
});

const DECLARED = {
  forked: {
    ecosystem: "npm",
    upstream: "lodash",
    version: "4.17.20",
    why: "carries a fix not yet released",
  },
};

test("declarations need every field and npm as the ecosystem; commit is optional", () => {
  assert.deepEqual(parseDeclarations({}), []);
  const withCommit = { forked: { ...DECLARED.forked, commit: "0123abc" } };
  assert.equal(parseDeclarations(withCommit)[0].commit, "0123abc");
  for (const field of ["ecosystem", "upstream", "version", "why"]) {
    const missing = { forked: { ...DECLARED.forked } };
    delete missing.forked[field];
    assert.throws(() => parseDeclarations(missing), new RegExp(`${field} is required`), field);
  }
  const bad = {
    "blank commit": { forked: { ...DECLARED.forked, commit: "" } },
    "other ecosystem": { forked: { ...DECLARED.forked, ecosystem: "Go" } },
    "unknown field": { forked: { ...DECLARED.forked, verison: "1" } },
    "not an object": { forked: "lodash" },
    "a list": [],
  };
  for (const [label, data] of Object.entries(bad)) {
    assert.throws(() => parseDeclarations(data), /advisory-sources\.json/, label);
  }
});

test("an undeclared non-registry dependency fails, and so does a stale declaration", () => {
  const deps = [{ name: "forked", source: "git+ssh://x" }, { name: "other", source: "file:o.tgz" }];
  const declarations = parseDeclarations({ ...DECLARED, gone: DECLARED.forked });
  assert.deepEqual(checkDeclarations(declarations, deps), [
    "other (file:o.tgz) does not come from the npm registry; " +
      "declare its upstream in advisory-sources.json",
    "advisory-sources.json: gone matches no non-registry dependency; remove it",
  ]);
  assert.deepEqual(checkDeclarations(parseDeclarations(DECLARED), deps.slice(0, 1)), []);
});

// Stands in for fetch: `answer(url, body)` returns [status, JSON body] or throws.
function stubFetch(answer) {
  const calls = [];
  const fetchFn = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body });
    const [status, data] = answer(url, body);
    return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(data) };
  };
  return { fetchFn, calls };
}

// Trimmed from the npm registry's bulk advisory answer for lodash 4.17.20 (2026-11-25).
const NPM_CONTROL_ANSWER = {
  lodash: [
    {
      id: 1106913,
      url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
      title: "Command Injection in lodash",
      severity: "high",
      vulnerable_versions: "<4.17.21",
    },
  ],
};
// Trimmed from OSV's /v1/query answer for npm lodash 4.17.20 (2026-11-25).
const OSV_CONTROL_ANSWER = {
  vulns: [
    {
      id: "GHSA-35jh-r3h4-6jhm",
      summary: "Command Injection in lodash",
      database_specific: { severity: "HIGH" },
    },
  ],
};

test("the npm advisory endpoint must return the control advisory", async () => {
  const ok = stubFetch(() => [200, NPM_CONTROL_ANSWER]);
  await checkNpmEndpoint(ok.fetchFn);
  assert.deepEqual(ok.calls, [{ url: NPM_ADVISORY_URL, body: { lodash: ["4.17.20"] } }]);
  await assert.rejects(checkNpmEndpoint(stubFetch(() => [200, {}]).fetchFn), /not answering/);
  await assert.rejects(checkNpmEndpoint(stubFetch(() => [503, {}]).fetchFn), /HTTP 503/);
  const down = stubFetch(() => {
    throw new TypeError("fetch failed");
  });
  await assert.rejects(checkNpmEndpoint(down.fetchFn), /fetch failed/);
});

test("OSV must return the control advisory; its answers are read page by page", async () => {
  await checkOsvEndpoint(stubFetch(() => [200, OSV_CONTROL_ANSWER]).fetchFn);
  const empty = stubFetch(() => [200, {}]);
  await assert.rejects(checkOsvEndpoint(empty.fetchFn), /OSV is not answering/);
  await assert.rejects(checkOsvEndpoint(stubFetch(() => [500, {}]).fetchFn), /HTTP 500/);
  const paged = stubFetch((url, body) => {
    assert.equal(url, OSV_QUERY_URL);
    assert.deepEqual(body.package, { name: "lodash", ecosystem: "npm" });
    if (!body.page_token) return [200, { next_page_token: "p2" }];
    return [200, OSV_CONTROL_ANSWER];
  });
  const vulns = await queryOsv("lodash", "4.17.20", paged.fetchFn);
  assert.deepEqual(vulns.map((v) => v.id), ["GHSA-35jh-r3h4-6jhm"]);
  assert.equal(paged.calls[1].body.page_token, "p2");
  const noId = stubFetch(() => [200, { vulns: [{ summary: "x" }] }]);
  await assert.rejects(queryOsv("lodash", "1", noId.fetchFn), /without an id/);
  const notList = stubFetch(() => [200, { vulns: {} }]);
  await assert.rejects(queryOsv("lodash", "1", notList.fetchFn), /not a list/);
});

test("an advisory against a declared fork's upstream release is a finding", async () => {
  const declarations = parseDeclarations(DECLARED);
  const findings = new Map();
  const osv = stubFetch(() => [200, OSV_CONTROL_ANSWER]);
  await collectDeclaredAdvisories(declarations, findings, osv.fetchFn);
  const { failures, findingIds } = evaluate(findings, []);
  assert.deepEqual(findingIds, ["GHSA-35jh-r3h4-6jhm"]);
  assert.deepEqual(failures, [
    "GHSA-35jh-r3h4-6jhm (high) forked (copy of lodash@4.17.20): Command Injection in lodash",
  ]);
  const ignores = parseIgnores({ "GHSA-35jh-r3h4-6jhm": entry() }, TODAY);
  assert.deepEqual(evaluate(findings, ignores).failures, []);
});

test("finding ids reach the workflow as one line separated by spaces", () => {
  const written = [];
  writeFindingIds("out", ["GHSA-82fw-gwwq-j7x9", "MAL-2026-1"], (f, t) => written.push([f, t]));
  writeFindingIds("out", [], (f, t) => written.push([f, t]));
  assert.deepEqual(written, [
    ["out", "finding_ids=GHSA-82fw-gwwq-j7x9 MAL-2026-1\n"],
    ["out", "finding_ids=\n"],
  ]);
});
