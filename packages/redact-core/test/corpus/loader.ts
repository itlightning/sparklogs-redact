// Loader for the shared redaction corpora. Not a test file: it only reads the fixtures next to it.
//
// PROVENANCE. Both corpora come from the SparkLogs source library, which shapes the same credential
// families on the collector side in VRL, and both are carried here verbatim so the two
// implementations can be held to one behavioural standard:
//
//   corpus.jsonl        the generated adversarial sweep (`tools/redaction-corpus.py`), one
//                       `{"message": ...}` object per line, in the generator's fixed emission order.
//   vrl-golden.txt      the collector's output for those cases, one JSON-encoded string per line,
//                       positionally aligned with corpus.jsonl.
//   vrl-fixtures.jsonl  the hand-written case files, as {case, input, vrl} triples.
//
// One file is local rather than carried:
//
//   deliberate-misses.jsonl  credential assignments this library knowingly does NOT redact, in the
//                            same {case, input, vrl} shape. They exist because a gate made only of
//                            cases we DO catch cannot price what a narrowing cost: the generated
//                            sweep is structurally blind to the unsigiled mid-line assignment, so
//                            retiring the detector that caught it moved nothing and looked free.
//                            Pinned here, the trade is visible, and widening a detector back over
//                            one of these shapes shows up as a golden diff rather than as silence.
//
// Values are SYNTHETIC. The generated sweep marks every credential position with ZZCREDZZ and every
// innocent neighbour with ZZNEIGHZZ, which is what lets a grader say which DIRECTION a change moved
// in rather than only that something moved: a surviving ZZCREDZZ is a leak, a missing ZZNEIGHZZ is
// an over-redaction, and the two are failures of equal weight.
//
// To refresh: regenerate in the source library, copy the three files, then re-run the golden script
// (`npm run regen-corpus-golden` at the repo root) and review the diff.

import fs from "node:fs";
import path from "node:path";
import type { RedactionResult } from "../../src/types.ts";

const DIR = import.meta.dirname;

function lines(file: string): string[] {
  return fs
    .readFileSync(path.join(DIR, file), "utf8")
    .split("\n")
    .filter((l) => l !== "");
}

export interface Case {
  /** Name of the source fixture case, for a readable failure message. */
  case: string;
  input: string;
  /** What the collector-side implementation produces, with `<redacted>` placeholders. */
  vrl: string;
}

/** The generated adversarial sweep, paired with the collector golden. */
export function generatedCases(): Case[] {
  const inputs = lines("corpus.jsonl").map((l) => JSON.parse(l).message as string);
  const golden = lines("vrl-golden.txt").map((l) => JSON.parse(l) as string);
  if (inputs.length !== golden.length) {
    throw new Error(`corpus/golden length mismatch: ${inputs.length} vs ${golden.length}`);
  }
  return inputs.map((input, i) => ({ case: `generated-${i}`, input, vrl: golden[i] }));
}

/** The hand-written case files. */
export function fixtureCases(): Case[] {
  return lines("vrl-fixtures.jsonl").map((l) => JSON.parse(l) as Case);
}

/** Shapes this library knowingly leaves alone; `vrl` is the input, unchanged. */
export function deliberateMisses(): Case[] {
  return lines("deliberate-misses.jsonl").map((l) => JSON.parse(l) as Case);
}

/** Every corpus, generated first, deliberate misses last. */
export function allCases(): Case[] {
  return [...generatedCases(), ...fixtureCases(), ...deliberateMisses()];
}

/**
 * Rewrite `text` with every redacted span replaced by the literal `<redacted>`, so JavaScript output
 * can be compared against a golden written by an implementation whose placeholder is that literal.
 * The correlated fakes are the product behaviour and are asserted elsewhere; here they are noise.
 */
export function normalize(text: string, result: RedactionResult): string {
  let out = "";
  let cursor = 0;
  for (const r of result.redactions) {
    out += text.slice(cursor, r.start) + "<redacted>";
    cursor = r.end;
  }
  return out + text.slice(cursor);
}
