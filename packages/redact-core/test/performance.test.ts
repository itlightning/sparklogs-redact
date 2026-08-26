// Cost tripwires. A JavaScript regex backtracks, so its cost is quadratic in the length of the run
// it scans, and the credential detectors are the ones with unbounded look-behinds in front of a
// value alternation. Both shapes below caught a real regression while the detectors were being
// written: an anchor whose variable-length separator offered one start position per space, and a
// value branch that re-scanned the line at each of them. The bounds are loose on purpose (slow CI,
// cold JIT); they are tripwires, not benchmarks.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { loadProfile } from "../src/detectors.ts";

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
  // A minified dump arrives as a SINGLE line, and nothing about the input can shorten it. This is
  // the shape that would hang a browser tab, so it gets its own tripwire: a pattern whose anchor or
  // value branch starts backtracking over a long run fails here long before anyone pastes one in.
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
