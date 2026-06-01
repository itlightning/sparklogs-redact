import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { loadProfile } from "../src/detectors.ts";

const r = () => new Redactor(loadProfile("windows-log"));

test("redact: emits one RedactionRecord per token, in document order, with offsets + masked + replacement", () => {
  const red = r();
  const input = "line one\n\\Users\\frank did x\n\\Users\\grace too";
  const res = red.redact(input);

  assert.equal(res.redactions.length, 2);

  const [first, second] = res.redactions;

  // Record 0 — frank on line 2.
  assert.equal(first.detector, "win-username-path");
  assert.equal(first.category, "username");
  assert.equal(first.line, 2);
  assert.equal(first.column, 8); // after the "\Users\" prefix on the line
  assert.equal(input.slice(first.start, first.end), "frank"); // offsets locate the ORIGINAL token
  assert.ok(!first.masked.includes("frank"), "masked never carries the raw token");
  assert.equal(first.masked, "fXXXX");
  assert.match(first.replacement, /^User\d+$/);
  assert.ok(res.text.includes(first.replacement), "replacement actually appears in the output");

  // Record 1 — grace on line 3.
  assert.equal(second.line, 3);
  assert.equal(input.slice(second.start, second.end), "grace");
  assert.notEqual(first.replacement, second.replacement); // distinct tokens -> distinct fakes
});

test("scan: hits carry 0-based start/end offsets that slice back to the raw token", () => {
  const red = r();
  const input = "x \\Users\\frank y";
  const hits = red.scan(input);
  assert.equal(hits.length, 1);
  const h = hits[0];
  assert.equal(input.slice(h.start, h.end), "frank");
  assert.equal(h.line, 1);
  assert.equal(typeof h.column, "number");
});

test("redact: clean text yields an empty redactions array and empty stats", () => {
  const red = r();
  const res = red.redact("nothing sensitive on this line at all");
  assert.deepEqual(res.redactions, []);
  assert.deepEqual(res.stats, {});
  assert.equal(res.mappingSize, 0);
});
