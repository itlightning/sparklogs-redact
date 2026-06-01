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
  /**
   * Name of a built-in validator (see validators.ts, e.g. "creditcard", "ssn") that the matched
   * token must pass to count as a real detection. Lets a broad regex stay precise: a candidate that
   * fails the check (a 16-digit run that fails Luhn, a 000-area "SSN") is skipped. Because the
   * format-shaped fakes are deliberately invalid (Luhn-fail / reserved area), the same validator
   * also makes redaction idempotent without a `safe` regex. Unknown names throw at compile time.
   */
  validate?: string;
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
  /**
   * One record per token replaced, in document order, describing WHERE (in the ORIGINAL text) each
   * redaction happened and WHAT it became. Carries no raw PII (`masked` only), so it is safe to keep
   * or transmit alongside the redacted output — downstream consumers (e.g. a browser UI that
   * highlights what will be removed before upload) use it to map redactions back onto the source.
   */
  redactions: RedactionRecord[];
}

/**
 * A located detection. Positions are 1-based line/column plus 0-based character `start`/`end`
 * offsets into the text that was scanned/redacted. `masked` is a shape-preserving mask, never raw.
 */
export interface ScanHit {
  detector: string;
  category: string;
  /** 1-based line number. */
  line: number;
  /** 1-based column (character offset within the line). */
  column: number;
  /** 0-based character offset of the token's first character. */
  start: number;
  /** 0-based character offset just past the token's last character. */
  end: number;
  /** A length-and-shape-preserving MASK of the token (never the raw value), e.g. "aXXXX". */
  masked: string;
}

/** A ScanHit enriched with the placeholder that replaced the token (the fake is not sensitive). */
export interface RedactionRecord extends ScanHit {
  /** The format-shaped fake substituted for the token. */
  replacement: string;
  /**
   * 0-based character offset of the replacement's first character within `RedactionResult.text`.
   * (`start`/`end` locate the token in the ORIGINAL text; these locate the fake in the OUTPUT, so a
   * UI can highlight the redacted side without re-scanning — the fakes are realistic and not
   * regex-recoverable.)
   */
  outStart: number;
  /** 0-based character offset just past the replacement's last character within `RedactionResult.text`. */
  outEnd: number;
}

/** Detected text encoding of a byte buffer. */
export interface EncodingInfo {
  encoding: "utf-8" | "utf-16le" | "utf-16be";
  /** Whether a byte-order mark was present at the start. */
  bom: boolean;
}
