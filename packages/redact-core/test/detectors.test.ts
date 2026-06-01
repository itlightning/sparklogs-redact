import { test } from "node:test";
import assert from "node:assert/strict";
import { loadProfile, profileNames, WINDOWS_LOG } from "../src/detectors.ts";

test("profileNames includes windows-log", () => {
  assert.ok(profileNames().includes("windows-log"));
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

test("every detector pattern compiles as a RegExp", () => {
  for (const d of loadProfile("windows-log")) {
    assert.doesNotThrow(() => new RegExp(d.pattern, (d.flags ?? "") + "g"));
    if (d.safe) assert.doesNotThrow(() => new RegExp(d.safe, "i"));
  }
});
