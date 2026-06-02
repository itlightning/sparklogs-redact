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
  // outStart/outEnd locate the fake in the OUTPUT text.
  assert.equal(res.text.slice(first.outStart, first.outEnd), first.replacement);

  // Record 1 — grace on line 3.
  assert.equal(second.line, 3);
  assert.equal(input.slice(second.start, second.end), "grace");
  assert.equal(res.text.slice(second.outStart, second.outEnd), second.replacement);
  assert.notEqual(first.replacement, second.replacement); // distinct tokens -> distinct fakes
});

test("redact: outStart/outEnd slice each replacement out of the redacted text, in order", () => {
  const red = r();
  // Mix of token lengths so replacement lengths differ from originals (offsets must shift).
  const input = "\\Users\\al \\Users\\bartholomew \\Users\\al";
  const res = red.redact(input);

  assert.ok(res.redactions.length >= 3);
  let prevEnd = -1;
  for (const rec of res.redactions) {
    assert.equal(
      res.text.slice(rec.outStart, rec.outEnd),
      rec.replacement,
      "output offsets must slice back to the replacement",
    );
    assert.ok(rec.outStart >= prevEnd, "records stay in document order, non-overlapping");
    prevEnd = rec.outEnd;
  }
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
