// Named token validators. A detector can reference one by name (Detector.validate); the engine runs
// it on each candidate match and skips the span if it returns false. This keeps a deliberately broad
// regex precise — e.g. "16 digits" only counts as a credit card if it passes Luhn — and, because the
// format-shaped fakes are built to FAIL these checks (Luhn-invalid card, reserved 000-area SSN),
// the same validator also makes redaction idempotent without a separate `safe` regex.
//
// Isomorphic; no external deps.

export type Validator = (token: string) => boolean;

/** Luhn (mod-10) checksum over the digits of a string (non-digits ignored). */
export function luhn(s: string): boolean {
  let sum = 0;
  let dbl = false;
  let seen = 0;
  for (let i = s.length - 1; i >= 0; i--) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) continue; // not 0-9
    let d = c - 48;
    seen++;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return seen > 0 && sum % 10 === 0;
}

/**
 * Real-credit-card check: Luhn-valid AND a plausible brand prefix + length. The length/prefix gate
 * roughly halves the residual Luhn false-positive rate on numeric-heavy logs without a full BIN table.
 */
function creditcard(token: string): boolean {
  const digits = token.replace(/\D/g, "");
  const n = digits.length;
  // Amex (15, 34/37); Visa/MC/Discover/JCB etc. (16); Visa (13/19); Diners (14).
  const len_ok = n === 13 || n === 14 || n === 15 || n === 16 || n === 19;
  if (!len_ok) return false;
  // Major Industry Identifier: 3=travel/Amex, 4=Visa, 5=MC, 6=Discover/Maestro. (0-2,7-9 are rare in
  // logs as card numbers and excluding them kills a lot of false positives.)
  if (!/^[3-6]/.test(digits)) return false;
  if (digits[0] === "3" && n !== 15 && n !== 14) return false; // Amex=15, Diners=14
  return luhn(digits);
}

/**
 * US SSN structure (the AAA-GG-SSSS shape is already enforced by the regex): reject the assignment
 * rules that mean "never a real SSN" — area 000/666/900-999, group 00, serial 0000. The fakes use
 * area 000 on purpose, so they fail here and are never re-redacted.
 */
function ssn(token: string): boolean {
  const m = token.match(/(\d{3})\D?(\d{2})\D?(\d{4})/);
  if (!m) return false;
  const area = +m[1];
  const group = +m[2];
  const serial = +m[3];
  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0) return false;
  if (serial === 0) return false;
  return true;
}

export const VALIDATORS: Record<string, Validator> = {
  luhn,
  creditcard,
  ssn,
};
