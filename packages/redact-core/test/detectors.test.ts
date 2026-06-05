import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { detectorCategories, loadProfile, profileNames, WINDOWS_LOG } from "../src/detectors.ts";

test("profileNames includes windows-log, generic, and secret", () => {
  for (const name of ["windows-log", "generic", "secret"]) {
    assert.ok(profileNames().includes(name), `missing profile ${name}`);
  }
});

test("loadProfile returns detectors for windows-log", () => {
  const detectors = loadProfile("windows-log");
  assert.ok(Array.isArray(detectors));
  assert.ok(detectors.length > 0);
  for (const d of detectors) {
    assert.equal(typeof d.name, "string");
    assert.equal(typeof d.category, "string");
    assert.equal(typeof d.pattern, "string");
  }
});

test("loadProfile throws on unknown profile", () => {
  assert.throws(() => loadProfile("nope"), /unknown profile/);
});

test("detectorCategories lists every category used by built-in profiles", () => {
  const cats = detectorCategories();
  assert.ok(cats.length > 0);
  assert.deepEqual(cats, [...cats].sort());
  assert.ok(cats.includes("username"));
  assert.ok(cats.includes("secret"));
  for (const name of profileNames()) {
    for (const d of loadProfile(name)) {
      assert.ok(cats.includes(d.category), `${name}/${d.name} category ${d.category}`);
    }
  }
});

test("WINDOWS_LOG export matches loadProfile", () => {
  assert.deepEqual(WINDOWS_LOG.detectors, loadProfile("windows-log"));
});

test("every detector pattern (every profile) compiles as a RegExp", () => {
  for (const name of profileNames()) {
    for (const d of loadProfile(name)) {
      assert.doesNotThrow(
        () => new RegExp(d.pattern, (d.flags ?? "") + "g"),
        `${name}/${d.name} pattern`,
      );
      if (d.safe) {
        const safe = d.safe;
        assert.doesNotThrow(() => new RegExp(safe, "i"), `${name}/${d.name} safe`);
      }
    }
  }
});

test("every profile builds a Redactor (resolves any referenced validators)", () => {
  // compile() throws on an unknown `validate` name, so constructing a Redactor per profile is the
  // cheapest end-to-end check that the JSON specs only reference built-in validators.
  for (const name of profileNames()) {
    assert.doesNotThrow(() => new Redactor(loadProfile(name)), `profile ${name} should compile`);
  }
});

test("unc-host: real UNC host is redacted, JSON doubled-backslash path segments are not", () => {
  const r = new Redactor(loadProfile("windows-log").filter((d) => d.category === "host"));
  // real UNC path \\SERVER\share
  assert.match(r.redact("open \\\\FILESERVER01\\share\\x").text, /^open \\\\HOST\d+\\share\\x$/);
  // JSON-escaped path (every separator doubled) must NOT match each segment as a host
  const json = '"\\\\\\\\?\\\\C:\\\\Windows\\\\CBS\\\\ACR\\\\file.cab"';
  assert.equal(r.redact(json).text, json, "JSON doubled-backslash path segments should be left intact");
});

test("win-username-path: well-known profile folders are safe; real account names redact", () => {
  const r = new Redactor(loadProfile("windows-log").filter((d) => d.category === "username"));
  const cbs =
    "GLOBALROOT/Device/HarddiskVolumeShadowCopy6/Users/Default/ntuser.dat from \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy6\\Users\\User00001\\ntuser.dat";
  assert.equal(r.redact(cbs).text, cbs, "CBS /Users/Default/ registry path should stay intact");
  assert.deepEqual(r.scan(cbs), []);

  for (const intact of [
    "open C:\\Users\\Public\\Documents\\file.txt",
    "path C:\\Users\\All Users\\Desktop\\x",
    "home C:\\Users\\defaultuser0\\AppData",
    "acct C:\\Users\\WDAGUtilityAccount\\Data",
    "admin C:\\Users\\Administrator\\Desktop",
    "/Users/Shared/foo",
    "/home/Guest/docs",
  ]) {
    assert.equal(r.redact(intact).text, intact, `should be intact: ${intact}`);
    assert.deepEqual(r.scan(intact), [], `scan clean: ${intact}`);
  }

  const red = r.redact("user \\Users\\alice logged in");
  assert.match(red.text, /\\Users\\User\d+/, "real username should redact");
  assert.notEqual(red.text, "user \\Users\\alice logged in");
});

test("fqdn-internal: only known-internal suffixes redact; filenames/public FQDNs stay intact", () => {
  const r = new Redactor(loadProfile("windows-log").filter((d) => d.category === "host"));
  // internal suffixes redact
  assert.match(r.redact("conn db01.corp.local ok").text, /HOST\d+/, ".local should redact");
  assert.match(r.redact("printer.home.arpa").text, /^HOST\d+$/, ".home.arpa should redact");
  assert.match(r.redact("svc.intranet up").text, /HOST\d+/, ".intranet should redact");
  // everything else stays intact (the key win over a public-TLD exclusion list)
  for (const intact of [
    "GET api.example.com/v1", // public FQDN
    "read config.json now", // filename
    "build x.OS.rs2.amd64.mfl", // dotted version/filename
    "app.config.prod restart", // non-internal dotted token
    "to redacted1@example.invalid", // the email fake domain (idempotency)
  ]) {
    assert.equal(r.redact(intact).text, intact, `should be intact: ${intact}`);
  }
});
