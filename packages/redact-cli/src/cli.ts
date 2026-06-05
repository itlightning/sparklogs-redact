#!/usr/bin/env node
// @sparklogs/redact-cli — thin Node wrapper around the isomorphic @sparklogs/redact-core. This is the
// ONLY Node-specific package (fs/process/stdin); the core stays browser-safe. Run via the built `bin`
// (dist/cli.js) after `npm run build`, or during development with `node src/cli.ts ...` once the
// workspace is linked and the core is built (Node >=23 strips the .ts types).
//
// Usage:
//   sparklogs-redact redact <input|-> [-o <output|->]      [--profile <name>] [--stats] [--report <f>]
//   sparklogs-redact redact <in...>  --out-dir <dir>        [--profile <name>] [--stats] [--report <f>]
//                                    [--save-map <f>] [--load-map <f>]   # shared correlation map
//   sparklogs-redact scan   <path...>                       [--profile <name> | --enable-all | --disable-categories list] [--max N] [--quiet]
//   sparklogs-redact profiles
//
// Multiple inputs (or --out-dir) redact through ONE correlation map, so the same real token gets the
// same pseudonym in every file. --save-map writes that map and --load-map seeds it from a prior run
// (to top up the SAME dataset later) — the map file CONTAINS RAW PII and must never be committed.
//
// --report <f> writes a JSON array of per-redaction records (file, detector, category, line/column,
// start/end offsets, a MASKED sample, and the replacement). It carries NO raw PII, so unlike the
// correlation map it is safe to keep — downstream tools use it to map redactions onto the source.
//
// Exit codes:  redact -> 0 ok.   scan -> 0 clean, 1 residual PII found, 2 usage/IO error.

import { readFileSync, writeFileSync, statSync, readdirSync, mkdirSync } from "node:fs";
import { join, basename } from "node:path";
import process from "node:process";
import {
  decode,
  Redactor,
  MappingEngine,
  loadProfile,
  profileNames,
  detectorCategories,
  type Detector,
  type RedactionRecord,
} from "@sparklogs/redact-core";

function fail(msg: string, code = 2): never {
  process.stderr.write(`sparklogs-redact: ${msg}\n`);
  process.exit(code);
}

/**
 * Compose EVERY detector from EVERY profile (deduped by detector name).
 */
function composeAllProfiles(): Detector[] {
  const byName = new Map<string, Detector>();
  for (const name of profileNames()) {
    for (const d of loadProfile(name)) if (!byName.has(d.name)) byName.set(d.name, d);
  }
  return [...byName.values()];
}

function parseCategoryList(raw: string): Set<string> {
  const known = new Set(detectorCategories());
  const out = new Set<string>();
  const invalid: string[] = [];
  for (const part of raw.split(",")) {
    const c = part.trim().toLowerCase();
    if (!c) continue;
    if (known.has(c)) out.add(c);
    else invalid.push(c);
  }
  if (invalid.length > 0) {
    fail(
      `unknown categor${invalid.length === 1 ? "y" : "ies"} in --disable-categories: ${invalid.join(", ")} ` +
        `(known: ${detectorCategories().join(", ")})`,
    );
  }
  if (out.size === 0) fail("empty --disable-categories list");
  return out;
}

interface DetectorRunOpts {
  profile: string;
  profileExplicit: boolean;
  enableAll: boolean;
  disableCategories: Set<string>;
}

/** Tri-mode detector selection: default profile | --enable-all | --disable-categories (all minus list). */
function detectorsForRun(opts: DetectorRunOpts): Detector[] {
  if (opts.enableAll && opts.disableCategories.size > 0) {
    fail("use --enable-all OR --disable-categories, not both");
  }
  if (opts.disableCategories.size > 0) {
    if (opts.profileExplicit) {
      fail("--disable-categories composes all profiles; do not combine with --profile");
    }
    return composeAllProfiles().filter((d) => !opts.disableCategories.has(d.category));
  }
  if (opts.enableAll) return composeAllProfiles();
  return loadProfile(opts.profile);
}

function takeDetectorRunOpts(args: string[]): DetectorRunOpts {
  const profileOpt = takeOpt(args, "--profile");
  const disableRaw = takeOpt(args, "--disable-categories");
  const enableAll = takeFlag(args, "--enable-all");
  const disableCategories = disableRaw ? parseCategoryList(disableRaw) : new Set<string>();
  return {
    profile: profileOpt ?? "windows-log",
    profileExplicit: profileOpt !== undefined,
    enableAll,
    disableCategories,
  };
}

function readBytes(path: string): Uint8Array {
  if (path === "-") {
    return new Uint8Array(readFileSync(0)); // fd 0 = stdin
  }
  return new Uint8Array(readFileSync(path));
}

/** Pull a `--flag value` (or `--flag=value`) out of args, returning the value and mutating args. */
function takeOpt(args: string[], name: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name) {
      const v = args[i + 1];
      args.splice(i, 2);
      return v;
    }
    if (args[i].startsWith(name + "=")) {
      const v = args[i].slice(name.length + 1);
      args.splice(i, 1);
      return v;
    }
  }
  return undefined;
}

function takeFlag(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i >= 0) {
    args.splice(i, 1);
    return true;
  }
  return false;
}

function walk(path: string, out: string[]): void {
  const st = statSync(path);
  if (st.isDirectory()) {
    for (const entry of readdirSync(path)) walk(join(path, entry), out);
  } else if (st.isFile()) {
    out.push(path);
  }
}

function cmdRedact(args: string[]): void {
  const outDir = takeOpt(args, "--out-dir");
  const out = takeOpt(args, "-o") ?? takeOpt(args, "--out");
  const saveMap = takeOpt(args, "--save-map");
  const loadMap = takeOpt(args, "--load-map");
  const report = takeOpt(args, "--report");
  const showStats = takeFlag(args, "--stats");
  const det = takeDetectorRunOpts(args);
  for (const a of args) {
    if (a.startsWith("--")) fail(`redact: unknown option ${a}`);
  }
  const inputs = args; // whatever remains after the options are consumed
  if (inputs.length === 0) fail("redact: missing <input> (use - for stdin)");
  const multi = inputs.length > 1 || outDir !== undefined;
  if (multi && inputs.includes("-")) {
    fail("redact: stdin (-) cannot be combined with multiple inputs / --out-dir");
  }
  if (inputs.length > 1 && !outDir) {
    fail("redact: multiple inputs require --out-dir <dir> (one redacted file out per input)");
  }
  if (out && multi) fail("redact: -o is for a single input; use --out-dir for multiple");

  const redactor = new Redactor(detectorsForRun(det));
  // One correlation map shared across every input in this invocation; optionally seeded from a prior
  // run so a later top-up of the SAME dataset keeps the same pseudonyms.
  let engine: MappingEngine;
  if (loadMap) {
    try {
      engine = MappingEngine.fromJSON(JSON.parse(readFileSync(loadMap, "utf-8")));
    } catch (e) {
      return fail(`redact: cannot load --load-map ${loadMap}: ${(e as Error).message}`);
    }
  } else {
    engine = new MappingEngine();
  }

  const agg: Record<string, number> = {};
  const tally = (s: Record<string, number>) => {
    for (const [k, v] of Object.entries(s)) agg[k] = (agg[k] ?? 0) + v;
  };
  // Per-redaction metadata (location + masked sample + replacement); carries no raw PII.
  const reportRecords: Array<{ file: string } & RedactionRecord> = [];

  if (multi) {
    mkdirSync(outDir!, { recursive: true });
    for (const input of inputs) {
      const res = redactor.redact(decode(readBytes(input)), engine);
      const dest = join(outDir!, basename(input));
      writeFileSync(dest, res.text, "utf-8");
      tally(res.stats);
      if (report) for (const r of res.redactions) reportRecords.push({ file: input, ...r });
      if (showStats) process.stderr.write(`  ${input} -> ${dest}\n`);
    }
  } else {
    const res = redactor.redact(decode(readBytes(inputs[0])), engine);
    tally(res.stats);
    if (report) for (const r of res.redactions) reportRecords.push({ file: inputs[0], ...r });
    const dest = out ?? "-";
    if (dest === "-") process.stdout.write(res.text);
    else writeFileSync(dest, res.text, "utf-8");
  }

  if (report) {
    writeFileSync(report, JSON.stringify(reportRecords, null, 2) + "\n", "utf-8");
    if (showStats) {
      process.stderr.write(`sparklogs-redact: wrote ${reportRecords.length} redaction record(s) to ${report}\n`);
    }
  }

  if (saveMap) {
    writeFileSync(saveMap, JSON.stringify(engine.toJSON()), "utf-8");
    process.stderr.write(
      `sparklogs-redact: wrote correlation map (${engine.size} token(s)) to ${saveMap} — ` +
        `this file CONTAINS RAW PII; never commit it.\n`,
    );
  }

  if (showStats) {
    const parts = Object.entries(agg)
      .sort()
      .map(([k, v]) => `${k}=${v}`);
    process.stderr.write(
      `redacted ${engine.size} distinct token(s) across ${inputs.length} input(s) ` +
        `[${parts.join(" ") || "none"}]\n`,
    );
  }
}

function cmdScan(args: string[]): void {
  const max = Number(takeOpt(args, "--max") ?? "50");
  const quiet = takeFlag(args, "--quiet");
  const det = takeDetectorRunOpts(args);
  if (args.length === 0) fail("scan: missing <path...>");
  for (const a of args) {
    if (a.startsWith("--")) fail(`scan: unknown option ${a}`);
  }

  const files: string[] = [];
  for (const p of args) walk(p, files);

  const redactor = new Redactor(detectorsForRun(det));
  let total = 0;
  let shown = 0;
  for (const f of files) {
    const text = decode(readBytes(f));
    const hits = redactor.scan(text);
    total += hits.length;
    for (const h of hits) {
      if (!quiet && shown < max) {
        process.stdout.write(`${f}:${h.line}:${h.column}: ${h.category} (${h.detector}) ~ ${h.masked}\n`);
        shown++;
      }
    }
  }
  if (total > 0) {
    process.stderr.write(
      `sparklogs-redact: FOUND ${total} residual PII hit(s) across ${files.length} file(s)` +
        (shown < total ? ` (showing ${shown})` : "") +
        `\n`,
    );
    process.exit(1);
  }
  if (!quiet) process.stdout.write(`scan clean: 0 residual PII across ${files.length} file(s)\n`);
}

function main(argv: string[]): void {
  const args = argv.slice(2);
  const cmd = args.shift();
  switch (cmd) {
    case "redact":
      return cmdRedact(args);
    case "scan":
      return cmdScan(args);
    case "profiles":
      process.stdout.write(profileNames().join("\n") + "\n");
      return;
    case undefined:
    case "-h":
    case "--help":
      process.stdout.write(
        "sparklogs-redact <command>\n\n" +
          "  redact <input|-> [-o out] [--profile name | --enable-all | --disable-categories list] [--stats] [--report f]\n" +
          "  redact <in...> --out-dir dir [--save-map f] [--load-map f] [--profile | --enable-all | --disable-categories] [--stats] [--report f]\n" +
          "  scan <path...> [--profile name | --enable-all | --disable-categories list] [--max N] [--quiet]\n" +
          "  profiles\n\n" +
          "  Profiles: " + profileNames().join(", ") + "\n" +
          "  Categories: " + detectorCategories().join(", ") + "\n" +
          "  Detector selection (mutually exclusive — pick one):\n" +
          "    (default)     --profile <name>  (windows-log when omitted)\n" +
          "    --enable-all                    every detector from every profile\n" +
          "    --disable-categories a,b,c      every profile, minus listed categories\n" +
          "  --disable-categories cannot be combined with --profile or --enable-all.\n" +
          "  CI fixture gate example: scan fixtures/ --disable-categories username,host\n" +
          "  Multiple inputs (or --out-dir) share one correlation map so a token maps the same in\n" +
          "  every file. --save-map/--load-map persist that map (RAW PII — never commit it).\n" +
          "  --report writes per-redaction metadata as JSON (no raw PII; safe to keep).\n",
      );
      return;
    default:
      fail(`unknown command ${JSON.stringify(cmd)} (try --help)`);
  }
}

main(process.argv);
