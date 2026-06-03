import { test } from "node:test";
import assert from "node:assert/strict";
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
  assert.ok(a && b);

  // "bob" -> same replacement in both files; "carol" differs.
  const bobA = a.redactions.find((r) => r.category === "username")!;
  const bobB = b.redactions.find((r) => r.category === "username")!;
  assert.equal(bobA.replacement, bobB.replacement, "same username -> same fake across files");

  const names = b.redactions.filter((r) => r.category === "username").map((r) => r.replacement);
  assert.equal(new Set(names).size, 2, "bob and carol map to two distinct fakes");

  // usage aggregate: the bob fake appears in both files.
  const u = s.usage.get(bobA.replacement)!;
  assert.equal(u.category, "username");
  assert.equal(u.files.size, 2);
});

test("runRedaction: totals count DISTINCT values per category", () => {
  const files = [{ id: "x", text: "\\Users\\bob \\Users\\bob \\Users\\amy 10.0.0.1 10.0.0.2" }];
  const s = runRedaction(files, PROFILES);
  // two distinct usernames (bob, amy) despite three occurrences.
  assert.equal(s.totals.username, 2);
  // two distinct ipv4s.
  assert.equal(s.totals.ipv4, 2);
  // mappingSize == distinct values overall.
  assert.equal(s.mappingSize, [...s.usage.keys()].length);
});

test("buildSegments: output offsets slice each pill to its replacement; originals recover via input offsets", () => {
  // Note: redact-core treats @example.com / @example.invalid as already-safe, so use a real domain.
  const input = "\\Users\\bob mailed alice@acme.io from 10.0.0.5";
  const s = runRedaction([{ id: "f", text: input }], PROFILES);
  const fr = s.byId.get("f")!;

  const segs = buildSegments(fr.text, fr.redactions, input);

  // Reassembling all segment text reproduces the redacted output exactly.
  assert.equal(segs.map((x) => x.text).join(""), fr.text);

  const pills = segs.filter((x) => x.pill);
  assert.ok(pills.length >= 3, "username, email, ipv4 should all be redacted");
  for (const seg of pills) {
    assert.equal(seg.text, seg.pill!.replacement, "pill text is the fake from the output");
    // the carried original is the real token sliced from the source by input offsets.
    assert.ok(seg.pill!.original && seg.pill!.original.length > 0);
    assert.ok(!fr.text.includes(seg.pill!.original!), "raw original is not present in redacted output");
  }
});
