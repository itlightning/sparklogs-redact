// @sparklogs/redact-core — public API (isomorphic; safe to import in Node or the browser).
//
// Detect + consistently pseudonymise PII in log text, with a residual-PII scanner. Detection is
// driven by portable JSON specs (see ../patterns); the consistent-mapping transform discards its
// lookup table after each pass (keyless determinism).

export type {
  Detector,
  Profile,
  RedactionResult,
  ScanHit,
  EncodingInfo,
} from "./types.ts";

export { detectEncoding, decode } from "./encoding.ts";
export { Redactor } from "./redact.ts";
export { FAKE_GENERATORS, MappingEngine } from "./fakes.ts";
export type { MappingSnapshot } from "./fakes.ts";
export { loadProfile, profileNames, WINDOWS_LOG } from "./detectors.ts";
