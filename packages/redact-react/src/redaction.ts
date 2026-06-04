// Redaction adapter over @sparklogs/redact-core. Runs every text file through ONE shared correlation
// map (redactMany), then derives the cross-file "usage" aggregate and per-category totals the
// preview UI needs — neither of which the core tracks, because they only matter to a batch UI.
import { Redactor, MappingEngine, loadProfile } from "@sparklogs/redact-core";
import type { Detector, RedactionRecord } from "@sparklogs/redact-core";
import type { ProfileName } from "./types.ts";

export interface FileRedaction {
  text: string;
  redactions: RedactionRecord[];
  stats: Record<string, number>;
}

/** One pseudonym's footprint across the batch. Keyed by the replacement (which is not sensitive). */
export interface UsageEntry {
  replacement: string;
  category: string;
  /** Total appearances across all files. */
  count: number;
  /** Ids of files the replacement appears in. */
  files: Set<string>;
}

export interface RedactionSummary {
  byId: Map<string, FileRedaction>;
  usage: Map<string, UsageEntry>;
  /** Distinct values redacted per category (== distinct replacements per category). */
  totals: Record<string, number>;
  /** Total distinct values redacted. */
  mappingSize: number;
}

/** Compose the named profiles into one detector list, de-duped by detector name. */
function detectorsFor(profiles: ProfileName[]): Detector[] {
  const byName = new Map<string, Detector>();
  for (const p of profiles) {
    for (const d of loadProfile(p)) {
      if (!byName.has(d.name)) byName.set(d.name, d);
    }
  }
  return [...byName.values()];
}

/** Distinct redaction categories the given profiles can emit — the universe for the rule toggles. */
export function redactionCategories(profiles: ProfileName[]): string[] {
  return [...new Set(detectorsFor(profiles).map((d) => d.category))];
}

/**
 * Redact a batch of text files together; returns redacted text + UI-facing aggregates. All files go
 * through ONE shared correlation map so the same token gets the same fake everywhere. `onProgress`,
 * if given, fires after each file (so a UI — or the worker — can report file-level progress).
 */
export function runRedaction(
  files: { id: string; text: string }[],
  profiles: ProfileName[],
  enabledCategories?: readonly string[] | null,
  onProgress?: (done: number, total: number) => void,
): RedactionSummary {
  let detectors = detectorsFor(profiles);
  if (enabledCategories) {
    const allow = new Set(enabledCategories);
    detectors = detectors.filter((d) => allow.has(d.category));
  }
  const redactor = new Redactor(detectors);
  const mapping = new MappingEngine();

  const byId = new Map<string, FileRedaction>();
  const usage = new Map<string, UsageEntry>();

  files.forEach((f, i) => {
    const res = redactor.redact(f.text, mapping);
    byId.set(f.id, { text: res.text, redactions: res.redactions, stats: res.stats });
    for (const rec of res.redactions) {
      let u = usage.get(rec.replacement);
      if (!u) {
        u = { replacement: rec.replacement, category: rec.category, count: 0, files: new Set() };
        usage.set(rec.replacement, u);
      }
      u.count++;
      u.files.add(f.id);
    }
    onProgress?.(i + 1, files.length);
  });

  const totals: Record<string, number> = {};
  for (const u of usage.values()) totals[u.category] = (totals[u.category] ?? 0) + 1;

  return { byId, usage, totals, mappingSize: usage.size };
}

/** A run of redacted text; `pill` is set on segments that are a replacement (for highlighting). */
export interface Segment {
  text: string;
  pill?: { category: string; replacement: string; original?: string };
}

/**
 * Slice redacted text into plain/pill segments using the OUTPUT offsets (`outStart`/`outEnd`). When
 * `originalText` is supplied, each pill carries the raw original (sliced from the source via the
 * input offsets) so the preview can offer a local-only "reveal".
 */
export function buildSegments(
  redactedText: string,
  redactions: RedactionRecord[],
  originalText?: string,
): Segment[] {
  const segs: Segment[] = [];
  const sorted = [...redactions].sort((a, b) => a.outStart - b.outStart);
  let last = 0;
  for (const r of sorted) {
    if (r.outStart > last) segs.push({ text: redactedText.slice(last, r.outStart) });
    const original = originalText != null ? originalText.slice(r.start, r.end) : undefined;
    segs.push({
      text: redactedText.slice(r.outStart, r.outEnd),
      pill: { category: r.category, replacement: r.replacement, original },
    });
    last = r.outEnd;
  }
  if (last < redactedText.length) segs.push({ text: redactedText.slice(last) });
  return segs;
}
