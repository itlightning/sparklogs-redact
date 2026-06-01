// Public types for @sparklogs/redact-core. Isomorphic (no Node/browser-only references here).

/**
 * A single PII detector. Its compiled regex's FULL match is the sensitive token — context that
 * locates the token (e.g. a `\Users\` prefix) is excluded with look-around, so a redactor can
 * replace `match[0]` directly without tracking capture-group offsets.
 */
export interface Detector {
  /** Stable identifier, e.g. "win-username-path". */
  name: string;
  /** Fake-value class — selects which generator produces the replacement, e.g. "username". */
  category: string;
  /** Regex source (the "g" flag is always added by the engine; do not include it here). */
  pattern: string;
  /** Extra regex flags, e.g. "i". */
  flags?: string;
  /**
   * Regex source matched against a token to decide it is ALREADY a redacted placeholder. Tokens
   * that match are skipped by both redact (idempotency) and scan (so the gate flags only
   * un-redacted, real-looking PII). Matched case-insensitively.
   */
  safe?: string;
  description?: string;
}

/** A detection profile = an ordered list of detectors plus metadata. */
export interface Profile {
  profile: string;
  version?: number;
  description?: string;
  detectors: Detector[];
}

/** Result of redacting a string. */
export interface RedactionResult {
  /** The redacted text. */
  text: string;
  /** category -> number of tokens replaced. */
  stats: Record<string, number>;
  /** Number of distinct original tokens that were mapped to a fake. */
  mappingSize: number;
}

/** A residual-PII finding (for the scan gate). */
export interface ScanHit {
  detector: string;
  category: string;
  /** 1-based line number. */
  line: number;
  /** 1-based column (character offset within the line). */
  column: number;
  /** A length-and-shape-preserving MASK of the token (never the raw value), e.g. "aXXXX". */
  masked: string;
}

/** Detected text encoding of a byte buffer. */
export interface EncodingInfo {
  encoding: "utf-8" | "utf-16le" | "utf-16be";
  /** Whether a byte-order mark was present at the start. */
  bom: boolean;
}
