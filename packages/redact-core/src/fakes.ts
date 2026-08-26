// Format-shaped fake generators. Each takes a 1-based per-category counter (first-seen order) and
// the original token, and returns a deterministic, structure-preserving placeholder drawn from a
// RESERVED space that the matching detector's `safe` regex recognizes (so redaction is idempotent
// and a residual-PII scan treats the placeholder as clean). Isomorphic; no external deps.

import { luhn } from "./validators.ts";

export type FakeGenerator = (n: number, original: string) => string;

// Both fakes live in RFC 5737 documentation ranges — addresses that never appear as REAL traffic, so
// the detector's `safe` regex can recognise a fake without ever colliding with a real IP (which is
// why we do NOT reuse the real RFC 1918 10/8 space for the "private" fake). The public/private
// character is preserved by WHICH documentation range we use.
function privateIpv4(n: number): string {
  // RFC 5737 TEST-NET-2 (198.51.100.0/24) — stands in for an RFC 1918 / private address.
  return "198.51.100." + (n & 0xff);
}

function documentationIpv4(n: number): string {
  // RFC 5737 TEST-NET-1 (192.0.2.0/24) — stands in for a public address.
  return "192.0.2." + (n & 0xff);
}

function isPrivateV4(ip: string): boolean {
  const m = ip.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const a = +m[1];
  const b = +m[2];
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 127) return true;
  return false;
}

/**
 * IPv6 fake in the RFC 3849 documentation range 2001:db8::/32, shaped to MIRROR the original's form
 * (full 8-group / compressed / IPv4-embedded) and carrying through any %zone — so a redacted address
 * still reads like the kind of address it replaced. The IPv4-mapped (::ffff:) prefix is preserved.
 */
function fakeIpv6(n: number, original: string): string {
  const pct = original.indexOf("%");
  const addr = pct >= 0 ? original.slice(0, pct) : original;
  const zone = pct >= 0 ? original.slice(pct) : ""; // includes the leading "%"
  const hex = (n & 0xffff).toString(16);
  let fake: string;
  if (/\d+\.\d+\.\d+\.\d+/.test(addr)) {
    const v4 = documentationIpv4(n); // 192.0.2.x doc range
    fake = /^::ffff:/i.test(addr) ? "::ffff:" + v4 : "2001:db8::" + v4;
  } else if (addr.includes("::")) {
    fake = "2001:db8::" + hex; // compressed form
  } else {
    fake = "2001:db8:0:0:0:0:0:" + hex; // full 8-group form (uncompressed)
  }
  return fake + zone;
}

/**
 * Credit-card fake: same length + separator layout as the original, a real-looking Visa-style 4-prefix
 * — but with a deliberately WRONG check digit so it FAILS Luhn. The `creditcard` validator therefore
 * rejects it, which is what keeps redaction idempotent (no `safe` regex needed for this category).
 */
function fakeCreditcard(n: number, original: string): string {
  const digitCount = (original.match(/\d/g) ?? []).length;
  let body = ("4000" + String(n)).slice(0, digitCount).padEnd(digitCount, "0");
  if (luhn(body)) {
    // bump the check digit (rightmost, never doubled) so the sum can no longer be ≡0 mod 10
    body = body.slice(0, -1) + String((Number(body[body.length - 1]) + 1) % 10);
  }
  let i = 0;
  return original.replace(/\d/g, () => body[i++] ?? "0");
}

/** SSN fake using the never-assigned 000 area, so the `ssn` validator rejects it (idempotent). */
function fakeSsn(n: number, original: string): string {
  const group = String((n % 99) + 1).padStart(2, "0"); // 01..99 (never 00)
  const serial = String((n % 9999) + 1).padStart(4, "0"); // 0001..9999 (never 0000)
  const sep = original.includes("-") ? "-" : original.includes(" ") ? " " : "";
  return `000${sep}${group}${sep}${serial}`;
}

/**
 * Phone fake. E.164 → reserved country code 999 (recognised by the e164 detector's `safe`); NANP →
 * the never-valid 000 area + the 555-01xx fiction range, preserving paren-vs-dash form. The 000 area
 * means the NANP detector (which requires a [2-9] area) won't re-match it.
 */
function fakePhone(n: number, original: string): string {
  if (original.trimStart().startsWith("+")) {
    return "+999" + String(n).padStart(8, "0"); // +999 + 8 digits = 12 (within 10-15)
  }
  const last4 = "01" + String(n % 100).padStart(2, "0"); // 01NN, fiction 555-01xx range
  return original.includes("(") ? `(000) 555-${last4}` : `000-555-${last4}`;
}

/**
 * A token BODY (the part after a vendor prefix) of exactly `len` chars: the REDACTED sentinel + the
 * per-token counter, zero-padded out to length. Pure [A-Za-z0-9], so it satisfies every vendor's
 * base62/base64url body charset, and it always contains "REDACTED" so the detector's `safe` skips it.
 */
function redTail(len: number, n: number): string {
  const seed = "REDACTED" + n;
  return seed.length >= len ? seed.slice(0, len) : seed + "0".repeat(len - seed.length);
}

/**
 * High-entropy credential fake. Shape-aware so the placeholder stays structurally valid for its kind
 * (a 3-segment JWT, a 20-char AKIA key, a vendor-prefixed API token) while embedding the literal
 * REDACTED sentinel — which every `token`/`secret` detector's `safe` ("REDACTED") recognises, so it
 * is never re-redacted or flagged. Vendor branches KEEP the documented prefix so a redacted log still
 * reads like "a <vendor> token was here".
 */
function fakeToken(n: number, original: string): string {
  if (/^ey[A-Za-z0-9_-]*\.[A-Za-z0-9_-]/.test(original)) {
    return `eyJREDACTEDheader${n}.REDACTEDpayload${n}.REDACTEDsignature${n}`;
  }
  if (/^A[KS]IA[0-9A-Z]{16}$/.test(original)) {
    return "AKIAREDACTED" + String(n).padStart(8, "0"); // 4 + REDACTED(8) + 8 digits = 20 chars
  }
  // GitHub fine-grained PAT must be tested before the classic gh*_ prefix (github_ != gh[pousr]).
  if (/^github_pat_/.test(original)) {
    return "github_pat_" + redTail(22, n) + "_" + redTail(59, n);
  }
  if (/^gh[pousr]_/.test(original)) {
    return original.slice(0, 4) + redTail(36, n); // keep ghp_/gho_/ghu_/ghs_/ghr_
  }
  if (/^glpat-/.test(original)) {
    return "glpat-" + redTail(20, n);
  }
  if (/^AIza/.test(original)) {
    return "AIza" + redTail(35, n);
  }
  if (/^xox[baprse]-/.test(original)) {
    return original.slice(0, 5) + redTail(24, n); // keep xoxb-/xoxp-/xoxa-/xoxr-/xoxs-/xoxe-
  }
  const stripe = original.match(/^[sr]k_(?:live|test)_/);
  if (stripe) {
    return stripe[0] + redTail(24, n);
  }
  if (/^sk-ant-/.test(original)) {
    return "sk-ant-" + redTail(24, n);
  }
  if (/^SK[0-9a-fA-F]{32}$/.test(original)) {
    return "SK" + redTail(32, n); // Twilio; the sentinel breaks the hex shape, so it is simply never re-matched
  }
  if (/^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/.test(original)) {
    return "SG." + redTail(22, n) + "." + redTail(43, n);
  }
  if (/^npm_/.test(original)) {
    return "npm_" + redTail(36, n);
  }
  // SparkLogs' own credentials. The region label survives because it names a data residency
  // boundary, which is diagnostic, and it is not part of the secret.
  const slRegion = original.match(/^sl_([a-z0-9]+)_/);
  if (slRegion) {
    return `sl_${slRegion[1]}_` + redTail(43, n);
  }
  if (/^slk_/.test(original)) {
    return "slk_" + redTail(64, n);
  }
  if (/^slr_/.test(original)) {
    return "slr_" + redTail(43, n) + "." + redTail(43, n);
  }
  return "REDACTEDTOKEN" + n;
}

/** Secret/password fake: a private-key block stays a block; a Slack webhook keeps its host; else a marker. */
function fakeSecret(n: number, original: string): string {
  if (/-----BEGIN [\s\S]*?PRIVATE KEY-----/i.test(original)) {
    return "-----BEGIN PRIVATE KEY-----\nREDACTED-PRIVATE-KEY-" + n + "\n-----END PRIVATE KEY-----";
  }
  if (/^https:\/\/hooks\.slack\.com\/services\//i.test(original)) {
    // Keep the (non-sensitive) host; redact the team/channel/token path segments.
    return "https://hooks.slack.com/services/T" + redTail(8, n) + "/B" + redTail(8, n) + "/" + redTail(24, n);
  }
  return "REDACTED-SECRET-" + n;
}

export const FAKE_GENERATORS: Record<string, FakeGenerator> = {
  // \Users\User00001 — pure-synthetic account name; matches the win-username-path `safe` regex.
  username: (n) => "User" + String(n).padStart(5, "0"),

  // S-1-5-21-0-0-0-<rid> — keeps the 8-part user-SID shape but zeroes the machine triplet, so the
  // `safe` regex (S-1-5-21-0-0-0-\d+) recognises it and a real SID (nonzero machine id) stands out.
  sid: (n) => "S-1-5-21-0-0-0-" + (1000 + n),

  email: (n) => "redacted" + n + "@example.invalid",

  host: (n) => "HOST" + String(n).padStart(4, "0"),

  // 00:00:5E:00:53:xx — RFC 7042 documentation MAC range.
  mac: (n) => "00:00:5E:00:53:" + ((n - 1) & 0xff).toString(16).padStart(2, "0").toUpperCase(),

  // Preserve the public/private character of the address (semantic structure).
  ipv4: (n, original) => (isPrivateV4(original) ? privateIpv4(n) : documentationIpv4(n)),

  ipv6: fakeIpv6,

  creditcard: fakeCreditcard,

  ssn: fakeSsn,

  phone: fakePhone,

  // High-entropy credentials (JWT/AWS key/bearer) and secrets (passwords/private keys).
  token: fakeToken,
  secret: fakeSecret,

  generic: (n) => "REDACTED" + n,
};

/**
 * Maps original tokens to consistent fakes within a single pass. The same (category, original) pair
 * always yields the same fake; the backing map is INTENDED to be discarded after the pass (keyless
 * determinism — no persisted lookup table that could re-identify anyone).
 */
/**
 * Serialized form of a MappingEngine. CONTAINS RAW PII (each `entries` key embeds an original token),
 * so it must never be committed; it exists only to carry a correlation map between redaction passes on
 * the SAME uncommitted source data (multi-file batch, or a later top-up — see Redactor.redactMany and
 * the CLI --save-map/--load-map).
 */
export interface MappingSnapshot {
  version: 1;
  /** [category + " " + original, fake] pairs. */
  entries: [string, string][];
  /** [category, last-used counter] pairs, so a resumed pass keeps numbering monotonic. */
  counters: [string, number][];
}

export class MappingEngine {
  private map = new Map<string, string>();
  private counters = new Map<string, number>();

  /** Get-or-create the fake for a token in a category. */
  fakeFor(category: string, original: string): string {
    const key = category + " " + original;
    const existing = this.map.get(key);
    if (existing !== undefined) return existing;
    const gen = FAKE_GENERATORS[category] ?? FAKE_GENERATORS.generic;
    const n = (this.counters.get(category) ?? 0) + 1;
    this.counters.set(category, n);
    const fake = gen(n, original);
    this.map.set(key, fake);
    return fake;
  }

  get size(): number {
    return this.map.size;
  }

  /** Snapshot the map for save/load. WARNING: contains raw PII; never persist where it could be committed. */
  toJSON(): MappingSnapshot {
    return {
      version: 1,
      entries: [...this.map.entries()],
      counters: [...this.counters.entries()],
    };
  }

  /** Rebuild an engine from a prior snapshot so a later pass reuses the same pseudonyms. */
  static fromJSON(snap: MappingSnapshot): MappingEngine {
    const e = new MappingEngine();
    for (const [k, v] of snap?.entries ?? []) e.map.set(k, v);
    for (const [k, n] of snap?.counters ?? []) e.counters.set(k, n);
    return e;
  }
}
