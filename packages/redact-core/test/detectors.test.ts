import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { loadProfile, profileNames, WINDOWS_LOG } from "../src/detectors.ts";

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
