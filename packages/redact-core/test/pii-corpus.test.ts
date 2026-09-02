// The PII corpus gate. What it holds, and why each claim needs its own failure:
//
//   GOLDEN        the exact output of every case under every pinned profile, so a detector or fake
//                 change is reviewed as a diff of the lines it moved. This is also the contract a
//                 server-side port is graded against: same spans AND same stand-ins.
//   KEEP          the lines that must survive byte-identical. Half of redaction is restraint, and a
//                 gate made only of values we redact cannot see an engine that has started eating
//                 order numbers, reserved SSN shapes, or its own output.
//   PLACEHOLDERS  the <host-1> / <user-2> / <client-A> / <ip-3> forms an AI client writes when it
//                 pseudonymises before sending. They carry the correlation the reader needs; an
//                 engine that redacts them destroys the report it was protecting.
//   IDEMPOTENCY   redacting the golden reproduces the golden. Text reaches this engine already
//                 swept, and a detector that re-anchors on its own fake compounds every pass.
//
// VACUITY. A golden test passes trivially on a truncated fixture, an empty golden, or a corpus that
// nothing matches, so those are checked before anything is compared: non-empty on both sides, equal
// lengths, aligned case names, and a floor on how many lines each profile actually changed.
//
// See test/corpus/CORPUS.md for where the corpora come from and how to regenerate them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { loadProfile } from "../src/detectors.ts";
import { PII_PROFILES, piiCases, piiGolden } from "./corpus/loader.ts";

/** Floors, not counts: raising one is free, lowering one is a decision someone has to make. */
const MIN_CASES = 400;
const MIN_KEEP_CASES = 100;
const MIN_CHANGED_LINES = 100;

const PLACEHOLDERS = ["<host-1>", "<user-2>", "<client-A>", "<ip-3>"];

const occurrences = (text: string, needle: string) => text.split(needle).length - 1;

test("pii: corpus and golden are present, aligned, and large enough to grade anything", () => {
  const cases = piiCases();
  const golden = piiGolden();
  assert.ok(cases.length >= MIN_CASES, `corpus has ${cases.length} cases; run npm run regen-pii-corpus`);
  assert.ok(golden.length > 0, "golden is empty: run npm run regen-pii-golden");
  assert.equal(golden.length, cases.length, "golden is stale: run npm run regen-pii-golden");
  for (const [i, c] of cases.entries()) {
    assert.equal(golden[i].case, c.case, `golden row ${i + 1} is out of order`);
  }
  assert.ok(
    cases.filter((c) => c.keep).length >= MIN_KEEP_CASES,
    "corpus has too few must-not-change cases to price restraint",
  );
});

for (const profile of PII_PROFILES) {
  test(`pii/${profile}: output matches the committed golden, case for case`, () => {
    const red = new Redactor(loadProfile(profile));
    const cases = piiCases();
    const golden = piiGolden();
    for (const [i, c] of cases.entries()) {
      assert.equal(red.redact(c.input).text, golden[i][profile], `${c.case} (line ${i + 1})`);
    }
  });

  test(`pii/${profile}: the golden actually redacts something`, () => {
    const cases = piiCases();
    const golden = piiGolden();
    const changed = golden.filter((row, i) => row[profile] !== cases[i].input).length;
    assert.ok(
      changed >= MIN_CHANGED_LINES,
      `only ${changed} golden lines differ from their input; the gate is grading nothing`,
    );
  });

  test(`pii/${profile}: lines marked keep survive byte-identical`, () => {
    const red = new Redactor(loadProfile(profile));
    const eaten: string[] = [];
    for (const c of piiCases()) {
      if (!c.keep) continue;
      const out = red.redact(c.input).text;
      if (out !== c.input) eaten.push(`${c.case}: ${JSON.stringify(c.input)} -> ${JSON.stringify(out)}`);
    }
    assert.equal(eaten.length, 0, eaten.slice(0, 5).join("\n"));
  });

  test(`pii/${profile}: client-written placeholders reach the reader intact`, () => {
    const red = new Redactor(loadProfile(profile));
    for (const c of piiCases()) {
      const out = red.redact(c.input).text;
      for (const p of PLACEHOLDERS) {
        assert.equal(
          occurrences(out, p),
          occurrences(c.input, p),
          `${c.case}: ${p} count changed in ${JSON.stringify(out)}`,
        );
      }
    }
  });

  test(`pii/${profile}: redacting the golden reproduces the golden`, () => {
    const red = new Redactor(loadProfile(profile));
    for (const row of piiGolden()) {
      assert.equal(red.redact(row[profile]).text, row[profile], `${row.case}`);
    }
  });
}
