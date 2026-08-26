// The corpus gates. Three separate claims, and each one fails for a different reason:
//
//   IDEMPOTENCY   redacting redacted text changes nothing. A browser may redact a paste that a
//                 collector already redacted, and a value may be swept twice on its way here, so a
//                 detector that re-anchors on its own placeholder would eat the document alive.
//                 This is a hard invariant of the engine, not a property of one profile.
//   DIRECTION     against the collector-side golden, per marker: a ZZCREDZZ that survives here but
//                 not there is a LEAK, a ZZNEIGHZZ that survives there but not here is an
//                 OVER-REDACTION, and neither is allowed to appear without a decision.
//   GOLDEN        the exact output of every case, so a deliberate change is reviewed as a diff.
//
// See test/corpus/loader.ts for where the cases and the collector golden come from.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { Redactor } from "../src/redact.ts";
import { loadProfile, profileNames } from "../src/detectors.ts";
import { allCases, generatedCases, normalize } from "./corpus/loader.ts";

const CRED = /ZZCREDZZ/g;
const NEIGH = /ZZNEIGHZZ/g;

// The three direction counters are pinned EXACTLY rather than bounded, so an improvement has to be
// recorded here and a regression cannot hide inside slack. Leaks and over-redactions are both
// heading for zero; parity is heading for the full corpus.
const LEAKS = 250;
const OVER_REDACTIONS = 81;
const PARITY = 1191;

const count = (text: string, marker: RegExp) => (text.match(marker) ?? []).length;

for (const profile of profileNames()) {
  test(`${profile}: redaction is a fixed point on its own output`, () => {
    const red = new Redactor(loadProfile(profile));
    for (const c of allCases()) {
      const once = red.redact(c.input).text;
      assert.equal(red.redact(once).text, once, `${c.case}: ${JSON.stringify(c.input)}`);
    }
  });
}

test("secret: credential leaks against the collector stay at the pinned count", () => {
  const red = new Redactor(loadProfile("secret"));
  const leaks: string[] = [];
  for (const c of generatedCases()) {
    const js = normalize(c.input, red.redact(c.input));
    if (count(js, CRED) > count(c.vrl, CRED)) leaks.push(`${c.case}: ${JSON.stringify(c.input)}`);
  }
  assert.equal(leaks.length, LEAKS, leaks.slice(0, 5).join("\n"));
});

test("secret: over-redactions against the collector stay at the pinned count", () => {
  const red = new Redactor(loadProfile("secret"));
  const eaten: string[] = [];
  for (const c of generatedCases()) {
    const js = normalize(c.input, red.redact(c.input));
    if (count(js, NEIGH) < count(c.vrl, NEIGH)) eaten.push(`${c.case}: ${JSON.stringify(c.input)}`);
  }
  assert.equal(eaten.length, OVER_REDACTIONS, eaten.slice(0, 5).join("\n"));
});

test("secret: output matches the committed golden, case for case", () => {
  const red = new Redactor(loadProfile("secret"));
  const goldenPath = path.join(import.meta.dirname, "corpus/js-golden.txt");
  const golden = fs
    .readFileSync(goldenPath, "utf8")
    .split("\n")
    .filter((l) => l !== "")
    .map((l) => JSON.parse(l) as string);
  const cases = allCases();
  assert.equal(golden.length, cases.length, "golden is stale: run npm run regen-corpus-golden");
  for (const [i, c] of cases.entries()) {
    assert.equal(normalize(c.input, red.redact(c.input)), golden[i], `${c.case} (line ${i + 1})`);
  }
});

test("secret: parity with the collector stays at the pinned count", () => {
  const red = new Redactor(loadProfile("secret"));
  let parity = 0;
  for (const c of allCases()) {
    if (normalize(c.input, red.redact(c.input)) === c.vrl) parity++;
  }
  assert.equal(parity, PARITY, `of ${allCases().length} cases reproducing the collector output`);
});
