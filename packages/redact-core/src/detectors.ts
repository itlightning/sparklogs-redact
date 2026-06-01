// Detection profiles. The portable JSON specs in ../patterns are the source of truth; this module
// just loads + indexes them. Add a profile by dropping a JSON file in ../patterns and registering
// it here.

import type { Detector, Profile } from "./types.ts";
import windowsLog from "../patterns/windows-log.json" with { type: "json" };

const PROFILES: Record<string, Profile> = {
  "windows-log": windowsLog as Profile,
};

/** Names of the built-in profiles. */
export function profileNames(): string[] {
  return Object.keys(PROFILES);
}

/** Return the detectors for a named profile (throws on an unknown name). */
export function loadProfile(name: string): Detector[] {
  const p = PROFILES[name];
  if (!p) {
    throw new Error(
      `unknown profile ${JSON.stringify(name)}; known profiles: ${profileNames().join(", ")}`,
    );
  }
  return p.detectors;
}

export { windowsLog as WINDOWS_LOG };
