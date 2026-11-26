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
  gate,
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

test("ignore entries name one advisory and carry a reason", () => {
  const bad = {
    "no reason": { "GHSA-82fw-gwwq-j7x9": { until: "2027-01-01" } },
    "blank reason": { "GHSA-82fw-gwwq-j7x9": { reason: "  ", until: "2027-01-01" } },
    "unparseable until": { "GHSA-82fw-gwwq-j7x9": entry("next spring") },
    "impossible date": { "GHSA-82fw-gwwq-j7x9": entry("2027-02-30") },
    "until not a string": { "GHSA-82fw-gwwq-j7x9": entry(20270101) },
    "reason only (old form)": { "GHSA-82fw-gwwq-j7x9": "r" },
    "vuln without its date part": { "GHSA-82fw-gwwq-j7x9": { reason: "r", vuln: "VULN-1" } },
    "vuln with a short date": { "GHSA-82fw-gwwq-j7x9": { reason: "r", vuln: "VULN-2026112-1" } },
    "vuln lower case": { "GHSA-82fw-gwwq-j7x9": { reason: "r", vuln: "vuln-20261125-1" } },
    "vuln not a string": { "GHSA-82fw-gwwq-j7x9": { reason: "r", vuln: 20261125 } },
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
  const deferred = { reason: "r", until: "2030-01-01", vuln: "VULN-20261125-12" };
  assert.doesNotThrow(() => parseIgnores({ "GHSA-82fw-gwwq-j7x9": deferred }, TODAY));
});

test("an entry with a reason and no date has no end and clears its advisory", () => {
  const ignores = parseIgnores({ "GHSA-82fw-gwwq-j7x9": { reason: "not reachable" } }, TODAY);
  assert.equal(ignores[0].until, undefined);
  const { failures, findingIds } = evaluate(collectAdvisories(report()), ignores);
  assert.deepEqual(findingIds, ["GHSA-qxg6-89mg-rqv8"]);
  assert.equal(failures.length, 1);
});

test("an ignore entry lapses on its until date, however far ahead that is", () => {
  const at = (until, today) => () => parseIgnores({ "GHSA-82fw-gwwq-j7x9": entry(until) }, today);
  assert.doesNotThrow(at("2026-11-26", TODAY));
  assert.throws(at("2026-11-25", TODAY), /lapsed on 2026-11-25/);
  assert.throws(at("2026-11-01", TODAY), /lapsed on 2026-11-01/);
  assert.doesNotThrow(at("2036-11-25", TODAY));
  assert.doesNotThrow(at("2028-02-29", "2028-02-28"));
  assert.throws(at("2028-02-29", "2028-02-29"), /lapsed on 2028-02-29/);
  assert.throws(at("2027-02-29", TODAY), /must be a date/);
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

test("discovery audits every package-lock.json and refuses files it cannot read", () => {
  const { lockDirs, manifestDirs, problems } = discover([
    "package.json",
    "package-lock.json",
    "packages/a/package.json",
    "tools/x/package.json",
    "tools/x/package-lock.json",
    "site/yarn.lock",
    "orphan/package-lock.json",
    "README.md",
    "site/bun.lockb",
    "tools/go.mod",
    "app/pubspec.yaml",
    "crate/Cargo.toml",
    "py/requirements-dev.txt",
    "py/pyproject.toml",
    "Pipfile",
    "Gemfile",
    "php/composer.json",
  ]);
  assert.deepEqual(lockDirs, [".", "tools/x", "orphan"]);
  assert.deepEqual(manifestDirs, [".", "packages/a", "tools/x"]);
  const other = (path) => `${path}: dependency file of an ecosystem this gate does not audit`;
  assert.deepEqual(problems, [
    "site/yarn.lock: lockfile kind not audited by this gate; use package-lock.json",
    "site/bun.lockb: lockfile kind not audited by this gate; use package-lock.json",
    other("tools/go.mod"),
    other("app/pubspec.yaml"),
    other("crate/Cargo.toml"),
    other("py/requirements-dev.txt"),
    other("py/pyproject.toml"),
    other("Pipfile"),
    other("Gemfile"),
    other("php/composer.json"),
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
const FORKED = "git+ssh://git@github.com/someone/forked.git#abc";
// A host that only starts like the registry's.
const LOOKALIKE = "https://registry.npmjs.org.example.invalid/lodash/-/lodash-4.17.21.tgz";
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
      "node_modules/forked": { resolved: FORKED },
      "node_modules/tarball": { resolved: "https://example.com/tarball-1.0.0.tgz" },
      "node_modules/lookalike": { resolved: LOOKALIKE },
      "node_modules/local-tgz": { resolved: "file:vendor/local-tgz-1.0.0.tgz" },
      "node_modules/outside": { link: true, resolved: "../elsewhere/outside" },
      "node_modules/vendored": { link: true, resolved: "vendor/vendored" },
      "node_modules/escape": { link: true, resolved: "packages/../../escape" },
      "packages/core/node_modules/unresolved": { version: "1.0.0" },
    },
  };
  assert.deepEqual(nonRegistryDependencies(lockfile, MANIFEST, "package-lock.json"), [
    { name: "forked", resolved: FORKED, source: FORKED },
    {
      name: "tarball",
      resolved: "https://example.com/tarball-1.0.0.tgz",
      source: "https://example.com/tarball-1.0.0.tgz",
    },
    { name: "lookalike", resolved: LOOKALIKE, source: LOOKALIKE },
    {
      name: "local-tgz",
      resolved: "file:vendor/local-tgz-1.0.0.tgz",
      source: "file:vendor/local-tgz-1.0.0.tgz",
    },
    { name: "outside", resolved: "../elsewhere/outside", source: "link to ../elsewhere/outside" },
    { name: "vendored", resolved: "vendor/vendored", source: "link to vendor/vendored" },
    { name: "escape", resolved: "packages/../../escape", source: "link to packages/../../escape" },
    { name: "unresolved", resolved: undefined, source: "no resolved source" },
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
    locked: FORKED,
    why: "carries a fix not yet released",
  },
};

test("declarations need every field, locked included, and npm; commit is optional", () => {
  assert.deepEqual(parseDeclarations({}), []);
  const withCommit = { forked: { ...DECLARED.forked, commit: "0123abc" } };
  assert.equal(parseDeclarations(withCommit)[0].commit, "0123abc");
  for (const field of ["ecosystem", "upstream", "version", "locked", "why"]) {
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
  const deps = [
    { name: "forked", resolved: FORKED, source: FORKED },
    { name: "other", resolved: "file:o.tgz", source: "file:o.tgz" },
  ];
  const declarations = parseDeclarations({ ...DECLARED, gone: DECLARED.forked });
  assert.deepEqual(checkDeclarations(declarations, deps), [
    "other (file:o.tgz) does not come from the npm registry; " +
      "declare its upstream in advisory-sources.json",
    "advisory-sources.json: gone matches no non-registry dependency; remove it",
  ]);
  assert.deepEqual(checkDeclarations(parseDeclarations(DECLARED), deps.slice(0, 1)), []);
});

test("a declaration whose locked value differs from the lockfile must be reviewed", () => {
  const moved = "git+ssh://git@github.com/someone/forked.git#def";
  const deps = [{ name: "forked", resolved: moved, source: moved }];
  assert.deepEqual(checkDeclarations(parseDeclarations(DECLARED), deps), [
    `advisory-sources.json: forked locks ${FORKED} but the lockfile resolves ${moved}; ` +
      "review the declared upstream version and update locked",
  ]);
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
    ["out", "findings=GHSA-82fw-gwwq-j7x9 MAL-2026-1\n"],
    ["out", "findings=\n"],
  ]);
});

// A whole repository for gate(): one workspace member, one registry dependency, npm and the two
// advisory endpoints stubbed. Each test changes one thing and expects the gate to notice.
function repo() {
  const lockfile = {
    lockfileVersion: 3,
    packages: {
      "": { name: "root", workspaces: ["packages/*"] },
      "packages/a": { version: "0.1.0" },
      "node_modules/@scope/a": { link: true, resolved: "packages/a" },
      "node_modules/lodash": reg("lodash", "4.17.21"),
    },
  };
  return {
    files: {
      "package.json": { name: "root", workspaces: ["packages/*"] },
      "package-lock.json": lockfile,
      "packages/a/package.json": { name: "@scope/a" },
      "advisory-ignore.json": {},
      "advisory-sources.json": {},
    },
    audit: { ...CLEAN, metadata: { ...CLEAN.metadata, dependencies: { total: 3 } } },
    npmAnswer: NPM_CONTROL_ANSWER,
    osvAnswer: () => OSV_CONTROL_ANSWER,
    output: [],
  };
}

async function runGate(r) {
  const env = {
    root: "/repo",
    readText: (path) => {
      if (!(path in r.files)) throw new Error(`ENOENT ${path}`);
      return JSON.stringify(r.files[path]);
    },
    trackedFiles: () => Object.keys(r.files),
    exec: () => JSON.stringify(r.audit),
    fetchFn: stubFetch((url, body) => [
      200,
      url === NPM_ADVISORY_URL ? r.npmAnswer : r.osvAnswer(body),
    ]).fetchFn,
    today: TODAY,
  };
  return gate(env, "out", (file, text) => r.output.push(text));
}

test("gate: a clean repository passes and writes an empty finding list", async () => {
  const r = repo();
  const { failures, summary } = await runGate(r);
  assert.deepEqual(failures, []);
  assert.match(summary, /^3 packages in 1 lockfile\(s\), 0 declared source\(s\)/);
  assert.deepEqual(r.output, ["findings=\n"]);
});

test("gate: an advisory fails and its id reaches the output file", async () => {
  const r = repo();
  r.audit = { ...report(), metadata: { ...report().metadata, dependencies: { total: 3 } } };
  const { failures } = await runGate(r);
  assert.equal(failures.length, 2);
  assert.deepEqual(r.output, ["findings=GHSA-82fw-gwwq-j7x9 GHSA-qxg6-89mg-rqv8\n"]);
});

test("gate: an undeclared non-registry dependency fails", async () => {
  const r = repo();
  r.files["package-lock.json"].packages["node_modules/forked"] = { resolved: FORKED };
  r.audit.metadata.dependencies.total = 4;
  const { failures } = await runGate(r);
  assert.deepEqual(failures.length, 1);
  assert.match(failures[0], /^forked \(git\+ssh:.*\) does not come from the npm registry/);
});

test("gate: an npm advisory endpoint that answers empty fails", async () => {
  const r = repo();
  r.npmAnswer = {};
  const { failures } = await runGate(r);
  assert.match(failures.join("\n"), /advisories\/bulk: no GHSA-35jh-r3h4-6jhm/);
});

test("gate: an audit covering fewer packages than the lockfile fails", async () => {
  const r = repo();
  r.audit.metadata.dependencies.total = 1;
  const { failures } = await runGate(r);
  assert.deepEqual(failures, ["npm audit: report covers 1 packages, lockfile lists 2"]);
});

test("gate: a tracked package.json no lockfile covers fails", async () => {
  const r = repo();
  r.files["packages/b/package.json"] = { name: "@scope/b" };
  const { failures } = await runGate(r);
  assert.deepEqual(failures, ["packages/b/package.json: no package-lock.json covers it"]);
});

test("gate: with a declaration, OSV must return the control advisory", async () => {
  const r = repo();
  r.files["package-lock.json"].packages["node_modules/forked"] = { resolved: FORKED };
  r.audit.metadata.dependencies.total = 4;
  r.files["advisory-sources.json"] = { forked: { ...DECLARED.forked, version: "4.18.1" } };
  r.osvAnswer = () => ({});
  const { failures } = await runGate(r);
  assert.match(failures.join("\n"), /api\.osv\.dev\/v1\/query: no GHSA-35jh-r3h4-6jhm/);
});

test("gate: an advisory against a declared upstream release fails", async () => {
  const r = repo();
  r.files["package-lock.json"].packages["node_modules/forked"] = { resolved: FORKED };
  r.audit.metadata.dependencies.total = 4;
  r.files["advisory-sources.json"] = DECLARED;
  const { failures } = await runGate(r);
  assert.deepEqual(failures, [
    "GHSA-35jh-r3h4-6jhm (high) forked (copy of lodash@4.17.20): Command Injection in lodash",
  ]);
  assert.deepEqual(r.output, ["findings=GHSA-35jh-r3h4-6jhm\n"]);
});

test("gate: an error becomes a failure line and leaves the finding list empty", async () => {
  const r = repo();
  delete r.files["advisory-sources.json"];
  const { failures } = await runGate(r);
  assert.deepEqual(failures, ["ENOENT advisory-sources.json"]);
  assert.deepEqual(r.output, ["findings=\n"]);
});
