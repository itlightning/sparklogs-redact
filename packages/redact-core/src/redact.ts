// The redaction engine: detect tokens, map each to a consistent format-shaped fake, rewrite the
// text. Also exposes scan() for a residual-PII gate. Isomorphic (pure string/regex work).

import type { Detector, RedactionRecord, RedactionResult, ScanHit } from "./types.ts";
import { MappingEngine } from "./fakes.ts";
import { VALIDATORS, type Validator } from "./validators.ts";

interface CompiledDetector {
  name: string;
  category: string;
  re: RegExp; // always global
  safe?: RegExp; // case-insensitive
  validate?: Validator; // candidate must pass to count as a detection
}

interface Span {
  start: number;
  end: number;
  detector: string;
  category: string;
  original: string;
}

function compile(detectors: Detector[]): CompiledDetector[] {
  return detectors.map((d) => {
    const flags = (d.flags ?? "").replace(/g/g, "") + "g";
    let validate: Validator | undefined;
    if (d.validate) {
      validate = VALIDATORS[d.validate];
      if (!validate) {
        throw new Error(
          `detector ${JSON.stringify(d.name)} references unknown validator ${JSON.stringify(
            d.validate,
          )}; known validators: ${Object.keys(VALIDATORS).join(", ")}`,
        );
      }
    }
    return {
      name: d.name,
      category: d.category,
      re: new RegExp(d.pattern, flags),
      safe: d.safe ? new RegExp(d.safe, "i") : undefined,
      validate,
    };
  });
}

/**
 * Collect every match across detectors as a token span. Already-redacted (safe) tokens are skipped.
 *
 * Every detector scans the WHOLE document. Scanning line by line was tried and withdrawn: a
 * backtracking regex is quadratic in the length of the run it scans, but every pattern here already
 * refuses to cross a line break, so the whole-document haystack never backtracks across one and
 * splitting it bought nothing while costing the slicing. What actually bounds the cost of a long
 * line is a zero-width test at the head of a pattern, ahead of its unbounded look-behind, so that a
 * long run of spaces is rejected once per position instead of re-scanned. `test/performance.test.ts`
 * is the tripwire for both shapes.
 */
function collectSpans(text: string, compiled: CompiledDetector[]): Span[] {
  const spans: Span[] = [];
  for (const d of compiled) {
    d.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = d.re.exec(text)) !== null) {
      const original = m[0];
      if (original.length === 0) {
        d.re.lastIndex++; // guard against zero-width loops
        continue;
      }
      if (d.safe && d.safe.test(original)) continue; // already a placeholder
      if (d.validate && !d.validate(original)) continue; // failed the structural check (e.g. Luhn)
      spans.push({
        start: m.index,
        end: m.index + original.length,
        detector: d.name,
        category: d.category,
        original,
      });
    }
  }
  return spans;
}

/**
 * Resolve overlaps deterministically: sort by start (then longer-first, then detector name), then
 * greedily accept spans that do not overlap an already-accepted one. Keeps replacement unambiguous.
 * The name is the final tiebreak because two detectors CAN claim the identical span, and which one
 * wins picks the fake's category; without it the winner would depend on the order the spans were
 * collected in, which is an implementation detail.
 */
function resolveOverlaps(spans: Span[]): Span[] {
  const sorted = spans.slice().sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    const byLength = b.end - b.start - (a.end - a.start);
    if (byLength !== 0) return byLength;
    return a.detector < b.detector ? -1 : a.detector > b.detector ? 1 : 0;
  });
  const accepted: Span[] = [];
  let lastEnd = -1;
  for (const s of sorted) {
    if (s.start >= lastEnd) {
      accepted.push(s);
      lastEnd = s.end;
    }
  }
  return accepted;
}

export class Redactor {
  private compiled: CompiledDetector[];

  constructor(detectors: Detector[]) {
    this.compiled = compile(detectors);
  }

  /**
   * Redact text: every detected token becomes a consistent, format-shaped fake.
   *
   * Pass a shared `mapping` to keep pseudonyms consistent ACROSS calls (multi-file batch / resumed
   * pass); omit it and a fresh, single-pass map is used and discarded (the keyless-determinism
   * default). Either way the same (category, original) within reach of the map yields the same fake.
   */
  redact(text: string, mapping: MappingEngine = new MappingEngine()): RedactionResult {
    const accepted = resolveOverlaps(collectSpans(text, this.compiled));
    // first-seen order == sorted-by-start (accepted is already start-ordered) => deterministic fakes
    const stats: Record<string, number> = {};
    const redactions: RedactionRecord[] = [];
    const lineStarts = computeLineStarts(text);

    let out = "";
    let cursor = 0;
    for (const s of accepted) {
      const fake = mapping.fakeFor(s.category, s.original);
      out += text.slice(cursor, s.start);
      const outStart = out.length;
      out += fake;
      const outEnd = out.length;
      cursor = s.end;
      stats[s.category] = (stats[s.category] ?? 0) + 1;
      const line = upperBound(lineStarts, s.start);
      redactions.push({
        detector: s.detector,
        category: s.category,
        line,
        column: s.start - lineStarts[line - 1] + 1,
        start: s.start,
        end: s.end,
        masked: mask(s.original),
        replacement: fake,
        outStart,
        outEnd,
      });
    }
    out += text.slice(cursor);
    return { text: out, stats, mappingSize: mapping.size, redactions };
  }

  /**
   * Redact several texts through ONE shared correlation map, so the same real token gets the same
   * pseudonym in every file (and distinct real tokens never collide onto one pseudonym, which is the
   * trap when each file is redacted independently). Seed `mapping` from a prior snapshot to extend an
   * earlier batch. The map is the caller's to discard (or snapshot) after the batch.
   */
  redactMany(
    texts: string[],
    mapping: MappingEngine = new MappingEngine(),
  ): { results: RedactionResult[]; mapping: MappingEngine } {
    const results = texts.map((t) => this.redact(t, mapping));
    return { results, mapping };
  }

  /**
   * Residual-PII scan: report every detected token that is NOT already a redacted placeholder.
   * On a properly redacted fixture this returns []. The reported sample is MASKED, never raw.
   */
  scan(text: string): ScanHit[] {
    const spans = collectSpans(text, this.compiled);
    const hits: ScanHit[] = [];
    const lineStarts = computeLineStarts(text);
    for (const s of spans) {
      const line = upperBound(lineStarts, s.start); // 1-based
      hits.push({
        detector: s.detector,
        category: s.category,
        line,
        column: s.start - lineStarts[line - 1] + 1,
        start: s.start,
        end: s.end,
        masked: mask(s.original),
      });
    }
    hits.sort((a, b) => {
      if (a.line !== b.line) return a.line - b.line;
      if (a.column !== b.column) return a.column - b.column;
      if (a.end !== b.end) return a.end - b.end;
      return a.detector < b.detector ? -1 : a.detector > b.detector ? 1 : 0;
    });
    return hits;
  }
}

/** Offsets at which each line begins (index 0 => line 1), for line/column mapping. */
function computeLineStarts(text: string): number[] {
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  }
  return lineStarts;
}

/** Largest index i (1-based) such that lineStarts[i-1] <= pos. */
function upperBound(lineStarts: number[], pos: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= pos) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** Mask a token to its shape: keep first char, replace the rest with X, cap length. Never raw. */
function mask(token: string): string {
  if (token.length <= 1) return "X";
  const head = token[0];
  const tailLen = Math.min(token.length - 1, 8);
  return head + "X".repeat(tailLen);
}
