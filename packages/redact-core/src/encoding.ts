// Encoding detection + decoding. Isomorphic: uses only Uint8Array + the WHATWG TextDecoder
// (available in Node >=18 and every modern browser). No Node Buffer, no fs.

import type { EncodingInfo } from "./types.ts";

const BOM_UTF8 = [0xef, 0xbb, 0xbf];
const BOM_UTF16LE = [0xff, 0xfe];
const BOM_UTF16BE = [0xfe, 0xff];

function startsWith(bytes: Uint8Array, sig: number[]): boolean {
  if (bytes.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (bytes[i] !== sig[i]) return false;
  }
  return true;
}

/**
 * Detect the encoding of a byte buffer. Prefers an explicit BOM; otherwise uses a NUL-byte
 * heuristic (UTF-16 text has frequent NULs in one byte-lane), defaulting to UTF-8.
 */
export function detectEncoding(bytes: Uint8Array): EncodingInfo {
  if (startsWith(bytes, BOM_UTF8)) return { encoding: "utf-8", bom: true };
  // UTF-16LE and UTF-32LE share the FF FE prefix; we only target text logs, so treat as UTF-16LE.
  if (startsWith(bytes, BOM_UTF16LE)) return { encoding: "utf-16le", bom: true };
  if (startsWith(bytes, BOM_UTF16BE)) return { encoding: "utf-16be", bom: true };

  // No BOM: sample the head and look at which byte-lane carries the NULs. ASCII-heavy UTF-16LE
  // has NULs at odd offsets (0x41 0x00); UTF-16BE at even offsets (0x00 0x41).
  const sample = Math.min(bytes.length, 4096);
  let nulOdd = 0;
  let nulEven = 0;
  let nulTotal = 0;
  for (let i = 0; i < sample; i++) {
    if (bytes[i] === 0x00) {
      nulTotal++;
      if (i % 2 === 0) nulEven++;
      else nulOdd++;
    }
  }
  // Real UTF-8 log text effectively never contains NUL; a meaningful NUL fraction => UTF-16.
  if (sample > 0 && nulTotal / sample > 0.1) {
    return { encoding: nulOdd >= nulEven ? "utf-16le" : "utf-16be", bom: false };
  }
  return { encoding: "utf-8", bom: false };
}

/**
 * Decode bytes to a string using the detected encoding. The BOM is stripped (TextDecoder does this
 * by default when `ignoreBOM` is false), so callers get clean text regardless of input encoding.
 */
export function decode(bytes: Uint8Array): string {
  const info = detectEncoding(bytes);
  // TextDecoder strips a leading BOM for utf-8/utf-16le/utf-16be when ignoreBOM is false (default).
  const decoder = new TextDecoder(info.encoding, { fatal: false });
  return decoder.decode(bytes);
}
