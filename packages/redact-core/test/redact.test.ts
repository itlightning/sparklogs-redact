import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { loadProfile } from "../src/detectors.ts";

function redactor(): Redactor {
  return new Redactor(loadProfile("windows-log"));
}

test("redacts a username in a \\Users\\ path", () => {
  const r = redactor();
  const out = r.redact("C:\\Users\\alice\\AppData\\Local\\Temp");
  assert.equal(out.text, "C:\\Users\\User00001\\AppData\\Local\\Temp");
  assert.equal(out.stats.username, 1);
});

test("redacts a user SID, zeroing the machine triplet", () => {
  const r = redactor();
  const out = r.redact("owner S-1-5-21-1004336348-1177238915-682003330-1001 done");
  assert.match(out.text, /S-1-5-21-0-0-0-\d+/);
  assert.equal(out.stats.sid, 1);
});

test("does not redact system SIDs (only S-1-5-21 user SIDs)", () => {
  const r = redactor();
  const text =
    "LocalSystem S-1-5-18 LocalService S-1-5-19 NetworkService S-1-5-20 " +
    "admins S-1-5-32-544 service S-1-5-80-1234567890-1234567890-1234567890-1234567890-1234567890";
  const out = r.redact(text);
  assert.equal(out.text, text);
  assert.equal(out.mappingSize, 0);
  assert.deepEqual(r.scan(text), []);
});

test("does not redact dotted-quad version strings (no IPv4 detector)", () => {
  const r = redactor();
  const text = "Package version 10.0.0.0 and 6.4.1.0 installed";
  const out = r.redact(text);
  assert.equal(out.text, text);
});

test("consistent mapping: same token -> same fake; distinct tokens differ", () => {
  const r = redactor();
  const out = r.redact("\\Users\\bob x \\Users\\carol y \\Users\\bob");
  // bob appears twice and must map to the same fake; carol gets a different one.
  const m = out.text.match(/\\Users\\(User\d+)/g)!;
  assert.equal(m.length, 3);
  assert.equal(m[0], m[2]); // both "bob" occurrences identical
  assert.notEqual(m[0], m[1]); // "carol" distinct
  assert.equal(out.mappingSize, 2);
});

test("redaction is idempotent (safe placeholders are not re-redacted)", () => {
  const r = redactor();
  const once = r.redact("\\Users\\dave email dave@corp.example.org SID S-1-5-21-9-8-7-1005");
  const twice = r.redact(once.text);
  assert.equal(twice.text, once.text);
});

test("scan reports zero residual PII after redaction", () => {
  const r = redactor();
  const raw =
    "\\Users\\erin opened \\\\FILESRV01\\share mac 0A:1B:2C:3D:4E:5F sid S-1-5-21-1-2-3-1100";
  const out = r.redact(raw);
  const hits = r.scan(out.text);
  assert.deepEqual(hits, []);
});

test("scan flags real un-redacted PII with masked sample + position", () => {
  const r = redactor();
  const hits = r.scan("line one\n\\Users\\frank here");
  assert.equal(hits.length, 1);
  const h = hits[0];
  assert.equal(h.category, "username");
  assert.equal(h.line, 2);
  // masked never reveals the raw token: keep first char, rest become X
  assert.doesNotMatch(h.masked, /frank/);
  assert.match(h.masked, /^fX+$/);
});

test("redacts email into the reserved example.invalid space", () => {
  const r = redactor();
  const out = r.redact("contact gwen@contoso.com please");
  assert.match(out.text, /redacted\d+@example\.invalid/);
  assert.equal(out.stats.email, 1);
});

test("redacts a UNC hostname but not device paths", () => {
  const r = redactor();
  const out = r.redact("\\\\WINBOX7\\public and \\\\?\\C:\\dev");
  assert.match(out.text, /\\\\HOST\d+\\public/);
  // device path host (\\?\) must be untouched
  assert.match(out.text, /\\\\\?\\C:\\dev/);
});

test("redacts a MAC address into the RFC 7042 doc range", () => {
  const r = redactor();
  const out = r.redact("nic 0A:1B:2C:3D:4E:5F up");
  assert.match(out.text, /00:00:5E:00:53:[0-9A-F]{2}/);
  assert.equal(out.stats.mac, 1);
});

test("overlapping detectors resolve deterministically (no double-replacement)", () => {
  const r = redactor();
  // email contains an @host that could otherwise be partially matched; ensure single clean swap.
  const out = r.redact("user@\\Users\\nested");
  // the email detector should win the @-bearing region; result must be scan-clean
  assert.deepEqual(r.scan(out.text), []);
});

test("empty input yields empty output and empty stats", () => {
  const r = redactor();
  const out = r.redact("");
  assert.equal(out.text, "");
  assert.equal(out.mappingSize, 0);
  assert.deepEqual(out.stats, {});
});
