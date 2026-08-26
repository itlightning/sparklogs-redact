// The `lineBounded` speed contract: a detector that declares it must detect the SAME spans whether
// it is run against the whole document or against one line at a time. The declaration is what lets
// the engine keep a backtracking regex off a very long haystack, and it is a claim about the
// pattern, so it is proved here against every case both corpora carry rather than reviewed by eye.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { loadProfile, profileNames } from "../src/detectors.ts";
import type { Detector } from "../src/types.ts";
import { allCases } from "./corpus/loader.ts";

/** The same profile with every line-at-a-time declaration withdrawn: one haystack, whole document. */
function wholeDocument(name: string): Detector[] {
  return loadProfile(name).map((d) => ({ ...d, lineBounded: false }));
}

/** Documents built from the corpora, so a pattern gets real text ABOVE and BELOW every line. */
function documents(): string[] {
  const inputs = allCases().map((c) => c.input);
  const docs: string[] = [];
  for (let i = 0; i < inputs.length; i += 100) {
    const chunk = inputs.slice(i, i + 100);
    docs.push(chunk.join("\n"));
    docs.push(chunk.join("\r\n"));
  }
  // Line breaks at the edges: a leading, trailing and doubled break each move the line boundaries.
  docs.push("\n" + inputs.slice(0, 50).join("\n\n") + "\n");
  return docs;
}

for (const profile of profileNames()) {
  test(`${profile}: line-at-a-time detection equals whole-document detection`, () => {
    const perLine = new Redactor(loadProfile(profile));
    const whole = new Redactor(wholeDocument(profile));
    for (const doc of documents()) {
      assert.deepEqual(perLine.scan(doc), whole.scan(doc));
      assert.equal(perLine.redact(doc).text, whole.redact(doc).text);
    }
  });

  test(`${profile}: line-at-a-time detection equals whole-document detection, case by case`, () => {
    const perLine = new Redactor(loadProfile(profile));
    const whole = new Redactor(wholeDocument(profile));
    for (const c of allCases()) {
      assert.deepEqual(perLine.scan(c.input), whole.scan(c.input), c.case);
      assert.equal(perLine.redact(c.input).text, whole.redact(c.input).text, c.case);
    }
  });
}

test("a detector that is NOT lineBounded still sees across a line break", () => {
  // The negative half of the contract: withholding the declaration has to keep the whole document
  // as one haystack, or the equivalence above would be proved by an engine that never splits.
  const across: Detector = {
    name: "across",
    category: "generic",
    pattern: "BEGIN[\\s\\S]*?END",
    flags: "",
  };
  const whole = new Redactor([across]);
  const split = new Redactor([{ ...across, lineBounded: true }]);
  const text = "BEGIN\nsecret\nEND";
  assert.equal(whole.redact(text).text, "REDACTED1");
  assert.equal(split.redact(text).text, text, "split into lines, the pattern cannot span them");
});

/** Median wall time of one `redact` pass over `text`, after a warm-up pass. */
function perPassMs(red: Redactor, text: string, runs = 5): number {
  red.redact(text);
  const samples: number[] = [];
  for (let i = 0; i < runs; i++) {
    const started = performance.now();
    red.redact(text);
    samples.push(performance.now() - started);
  }
  samples.sort((a, b) => a - b);
  return samples[samples.length >> 1];
}

test("an ordinary large paste stays affordable", () => {
  // The product path: a browser redacting a pasted log before upload. Every line carries an anchor
  // for the widest detectors, so this measures matching work rather than a scan over empty text.
  const red = new Redactor(loadProfile("secret"));
  const line =
    "2026-08-25T10:00:00Z host app[9]: Password=hunter2xyz;Server=db01;Encrypt=true user=alice";
  const doc = Array.from({ length: 1500 }, (_, i) => `${line} seq=${i}`).join("\n");
  const ms = perPassMs(red, doc);
  assert.ok(ms < 400, `redacting ${doc.length} bytes of ordinary log took ${ms.toFixed(1)} ms`);
});

test("one pathological very long line stays affordable", () => {
  // A minified dump arrives as a SINGLE line, which no amount of line feeding can shorten, and a
  // backtracking regex is quadratic in the length of the run it scans. This is the shape that would
  // hang a browser tab, so it gets its own tripwire: a pattern whose value branch starts backtracking
  // over a long run fails here long before anyone pastes one in.
  const red = new Redactor(loadProfile("secret"));
  const filler = " ".repeat(8000);
  const oneLine = [
    `Password=${filler}tail`,
    `Authorization: Bearer ${filler}tail`,
    `{"apikey":"${filler}tail"}`,
  ].join(" && ");
  const ms = perPassMs(red, oneLine, 3);
  assert.ok(ms < 1500, `redacting one ${oneLine.length}-byte line took ${ms.toFixed(1)} ms`);
});
