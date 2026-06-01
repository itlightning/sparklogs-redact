// Multi-file redaction with a shared correlation map + save/load of that map.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { MappingEngine } from "../src/fakes.ts";
import { loadProfile } from "../src/detectors.ts";

const redactor = () => new Redactor(loadProfile("windows-log"));

test("redactMany: same real token gets the same pseudonym across files", () => {
  const a = "open C:\\Users\\alice\\app.log";
  const b = "again C:\\Users\\alice\\b.log and C:\\Users\\bob\\c.log";
  const { results } = redactor().redactMany([a, b]);

  // alice = first distinct username -> User00001 in BOTH files; bob = second -> User00002.
  assert.ok(results[0].text.includes("User00001"));
  assert.ok(results[1].text.includes("User00001"));
  assert.ok(results[1].text.includes("User00002"));
  assert.ok(!results[0].text.includes("alice"));
  assert.ok(!results[1].text.includes("alice"));
  assert.ok(!results[1].text.includes("bob"));
});

test("independent redact() collides distinct people onto the same fake — why the shared map matters", () => {
  const r = redactor();
  const x = r.redact("C:\\Users\\alice\\1.log"); // fresh map -> User00001
  const y = r.redact("C:\\Users\\bob\\1.log"); // fresh map -> ALSO User00001 (different person!)
  assert.ok(x.text.includes("User00001"));
  assert.ok(y.text.includes("User00001"));
});

test("save/load: a reloaded map reuses earlier pseudonyms for a later top-up", () => {
  const r = redactor();
  const e1 = new MappingEngine();
  const first = r.redact("C:\\Users\\alice\\first.log", e1); // alice -> User00001
  assert.ok(first.text.includes("User00001"));

  // Persist + reload (mimics --save-map then --load-map on a later batch).
  const snap = JSON.parse(JSON.stringify(e1.toJSON()));
  assert.equal(snap.version, 1);
  const e2 = MappingEngine.fromJSON(snap);

  // Same person -> same fake; a NEW person continues numbering monotonically (no collision with User00001).
  const later = r.redact("C:\\Users\\alice\\later.log and C:\\Users\\carol\\x.log", e2);
  assert.ok(later.text.includes("User00001")); // alice preserved
  assert.ok(later.text.includes("User00002")); // carol gets the next number, not a reused one
});

test("redact(text) without an engine stays single-pass (default fresh map)", () => {
  const r = redactor();
  const res = r.redact("C:\\Users\\dave\\x.log");
  assert.ok(res.text.includes("User00001"));
  assert.equal(res.mappingSize, 1);
});
