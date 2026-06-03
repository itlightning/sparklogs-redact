import { test, expect } from "vitest";
import { runRedaction, buildSegments } from "../src/redaction.ts";
import type { ProfileName } from "../src/types.ts";

const PROFILES: ProfileName[] = ["windows-log", "generic", "secret"];

test("runRedaction: one shared map gives the same fake for the same token across files", () => {
  const files = [
    { id: "a", text: "user \\Users\\bob logged in from 10.0.0.5" },
    { id: "b", text: "again \\Users\\bob and \\Users\\carol from 10.0.0.5" },
  ];
  const s = runRedaction(files, PROFILES);

  const a = s.byId.get("a")!;
  const b = s.byId.get("b")!;
  expect(a && b).toBeTruthy();

  // "bob" -> same replacement in both files; "carol" differs.
  const bobA = a.redactions.find((r) => r.category === "username")!;
  const bobB = b.redactions.find((r) => r.category === "username")!;
  expect(bobA.replacement, "same username -> same fake across files").toBe(bobB.replacement);

  const names = b.redactions.filter((r) => r.category === "username").map((r) => r.replacement);
  expect(new Set(names).size, "bob and carol map to two distinct fakes").toBe(2);

  // usage aggregate: the bob fake appears in both files.
  const u = s.usage.get(bobA.replacement)!;
  expect(u.category).toBe("username");
  expect(u.files.size).toBe(2);
});

test("runRedaction: totals count DISTINCT values per category", () => {
  const files = [{ id: "x", text: "\\Users\\bob \\Users\\bob \\Users\\amy 10.0.0.1 10.0.0.2" }];
  const s = runRedaction(files, PROFILES);
  // two distinct usernames (bob, amy) despite three occurrences.
  expect(s.totals.username).toBe(2);
  // two distinct ipv4s.
  expect(s.totals.ipv4).toBe(2);
  // mappingSize == distinct values overall.
  expect(s.mappingSize).toBe([...s.usage.keys()].length);
});

test("buildSegments: output offsets slice each pill to its replacement; originals recover via input offsets", () => {
  // Note: redact-core treats @example.com / @example.invalid as already-safe, so use a real domain.
  const input = "\\Users\\bob mailed alice@acme.io from 10.0.0.5";
  const s = runRedaction([{ id: "f", text: input }], PROFILES);
  const fr = s.byId.get("f")!;

  const segs = buildSegments(fr.text, fr.redactions, input);

  // Reassembling all segment text reproduces the redacted output exactly.
  expect(segs.map((x) => x.text).join("")).toBe(fr.text);

  const pills = segs.filter((x) => x.pill);
  expect(pills.length >= 3, "username, email, ipv4 should all be redacted").toBeTruthy();
  for (const seg of pills) {
    expect(seg.text, "pill text is the fake from the output").toBe(seg.pill!.replacement);
    // the carried original is the real token sliced from the source by input offsets.
    expect(seg.pill!.original && seg.pill!.original.length > 0).toBeTruthy();
    expect(!fr.text.includes(seg.pill!.original!), "raw original is not present in redacted output").toBeTruthy();
  }
});
