// The redaction engine: detect tokens, map each to a consistent format-shaped fake, rewrite the
// text. Also exposes scan() for a residual-PII gate. Isomorphic (pure string/regex work).

import type { Detector, RedactionResult, ScanHit } from "./types.ts";
import { MappingEngine } from "./fakes.ts";

interface CompiledDetector {
  name: string;
  category: string;
  re: RegExp; // always global
  safe?: RegExp; // case-insensitive
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
    return {
      name: d.name,
      category: d.category,
      re: new RegExp(d.pattern, flags),
      safe: d.safe ? new RegExp(d.safe, "i") : undefined,
    };
  });
}

/** Collect every match across detectors as a token span. Already-redacted (safe) tokens are skipped. */
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
 * Resolve overlaps deterministically: sort by start (then longer-first), then greedily accept spans
 * that do not overlap an already-accepted one. Keeps replacement unambiguous.
 */
function resolveOverlaps(spans: Span[]): Span[] {
  const sorted = spans.slice().sort((a, b) =>
    a.start !== b.start ? a.start - b.start : b.end - b.start - (a.end - a.start),
  );
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

    let out = "";
    let cursor = 0;
    for (const s of accepted) {
      const fake = mapping.fakeFor(s.category, s.original);
      out += text.slice(cursor, s.start) + fake;
      cursor = s.end;
      stats[s.category] = (stats[s.category] ?? 0) + 1;
    }
    out += text.slice(cursor);
    return { text: out, stats, mappingSize: mapping.size };
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
    // Precompute line starts for line/column mapping.
    const lineStarts: number[] = [0];
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
    }
    for (const s of spans) {
      const line = upperBound(lineStarts, s.start); // 1-based
      const column = s.start - lineStarts[line - 1] + 1;
      hits.push({
        detector: s.detector,
        category: s.category,
        line,
        column,
        masked: mask(s.original),
      });
    }
    hits.sort((a, b) => (a.line !== b.line ? a.line - b.line : a.column - b.column));
    return hits;
  }
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
