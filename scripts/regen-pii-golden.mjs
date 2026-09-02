#!/usr/bin/env node
// Rewrite the committed golden for the PII corpus.
//
//   npm run regen-pii-golden     # rewrite packages/redact-core/test/corpus/pii-golden.jsonl
//
// A SIBLING OF regen-corpus-golden.mjs RATHER THAN A BRANCH INSIDE IT. The two goldens are read
// under different rules and would not share a line of code. The credential golden is written
// through `normalize()`, which throws the fakes away and prints `<redacted>`, because what it grades
// is a DIRECTION against a collector that spells its placeholder that way. This golden keeps the
// fakes: the whole product behaviour of the PII profiles is which fake a value becomes and that the
// same value becomes the same fake, so a port that redacted the right spans with different
// stand-ins would still be wrong. Folding both into one script would mean one flag deciding which
// of two unrelated outputs gets written.
//
// ONE FILE, ONE ROW PER CASE, ONE COLUMN PER PROFILE. Per-profile files would have to be kept
// positionally aligned with each other and with the corpus by hand; a row keyed by profile name
// cannot drift, and a reader comparing what `generic` and `windows-log` do to the same line reads
// across rather than across files.
//
// Each line is redacted with a FRESH mapping, so the fake counters restart per line. That is the
// contract a server-side port can actually meet: it sees one message at a time and has no way to
// know what the previous message contained.

import fs from "node:fs";
import path from "node:path";
import { Redactor } from "../packages/redact-core/src/redact.ts";
import { loadProfile } from "../packages/redact-core/src/detectors.ts";
import { PII_PROFILES, piiCases } from "../packages/redact-core/test/corpus/loader.ts";

const OUT = path.join(import.meta.dirname, "../packages/redact-core/test/corpus/pii-golden.jsonl");

const redactors = new Map(PII_PROFILES.map((p) => [p, new Redactor(loadProfile(p))]));
const cases = piiCases();
if (cases.length === 0) throw new Error("pii-corpus.jsonl is empty; run npm run regen-pii-corpus");

const body = cases
  .map((c) => {
    const row = { case: c.case };
    for (const p of PII_PROFILES) row[p] = redactors.get(p).redact(c.input).text;
    return JSON.stringify(row) + "\n";
  })
  .join("");

fs.writeFileSync(OUT, body, "utf8");
process.stdout.write(`wrote ${cases.length} rows to ${OUT}\n`);
