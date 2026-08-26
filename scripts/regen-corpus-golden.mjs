#!/usr/bin/env node
// Rewrite the committed JavaScript golden for the redaction corpora.
//
// The golden is what turns "the corpus still passes" into "the corpus produces exactly this", so a
// pattern edit shows up as a reviewable diff of the LINES it moved rather than as a count. Run this
// after any deliberate detector change, then read the diff before committing it: a line that gained
// a placeholder is a new redaction, a line that lost ZZNEIGHZZ is a new over-redaction, and a line
// that gained ZZCREDZZ is a leak.
//
//   npm run regen-corpus-golden

import fs from "node:fs";
import path from "node:path";
import { Redactor } from "../packages/redact-core/src/redact.ts";
import { loadProfile } from "../packages/redact-core/src/detectors.ts";
import { allCases, normalize } from "../packages/redact-core/test/corpus/loader.ts";

const OUT = path.join(import.meta.dirname, "../packages/redact-core/test/corpus/js-golden.txt");

const red = new Redactor(loadProfile("secret"));
const body = allCases()
  .map((c) => JSON.stringify(normalize(c.input, red.redact(c.input))) + "\n")
  .join("");

fs.writeFileSync(OUT, body, "utf8");
process.stdout.write(`wrote ${body.split("\n").length - 1} lines to ${OUT}\n`);
