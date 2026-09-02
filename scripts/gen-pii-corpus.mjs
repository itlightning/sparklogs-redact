#!/usr/bin/env node
// Build the PII corpus that both this library and the server-side ports are graded against.
//
//   npm run regen-pii-corpus     # rewrite packages/redact-core/test/corpus/pii-corpus.jsonl
//
// WHY IT IS GENERATED. A hand-typed corpus grows where someone remembered to type, so it ends up
// dense in the shapes that were already understood and empty in the ones that matter: the same
// address in a quoted field and at the end of a line, the same card number with and without its
// grouping, the same path with a trailing newline. Crossing a table of VALUES with a table of
// CONTEXTS gets that coverage for free and keeps it reviewable, because a new value is one line
// here and shows up in every context at once.
//
// WHY SOME LINES MUST NOT CHANGE. Half of a redaction gate is what it leaves alone. A value group
// marked `keep` asserts byte-identical output under every profile, which is how the corpus prices
// the validators (a 16-digit number that fails Luhn is an order number, not a card), the reserved
// shapes (SSN area 000), the placeholders an AI client writes (`<host-1>`), and idempotency (text
// that is already this engine's own output).
//
// DIALECT. The same patterns run here on JavaScript regex, on the collector in Rust, and in Go
// ports. Those dialects disagree about what `\d` and `\b` mean outside ASCII and about where a line
// ends, so the corpus carries lines that can WITNESS the disagreement: non-ASCII digits in an
// SSN-shaped and a card-shaped run, an accented letter glued to a MAC address, a token followed by
// each of the terminators the engines rank differently (\n, bare \r, \r\n, U+2028, U+2029), and
// characters above U+FFFF beside and inside tokens, where UTF-16, UTF-8 and rune offsets stop
// agreeing on where a span starts. A port whose dialect differs produces a different golden line,
// which is the whole point of committing one.
//
// EVERY VALUE IS SYNTHETIC and drawn from a documentation or reserved range. Addresses that this
// engine treats as ALREADY redacted (RFC 5737 TEST-NET, RFC 3849 2001:db8::/32, example.com) cannot
// double as detection inputs, so detection cases use other never-routed ranges: RFC 2544
// benchmarking (198.18.0.0/15), RFC 6598 shared address space (100.64.0.0/10), RFC 1918 private
// space, RFC 4193 unique-local IPv6, and the RFC 2606 example.net / example.org domains. Card
// numbers are the vendors' published test numbers.

import fs from "node:fs";
import path from "node:path";

const OUT = path.join(
  import.meta.dirname,
  "../packages/redact-core/test/corpus/pii-corpus.jsonl",
);

/**
 * Contexts every token value is placed in. Deliberately free of anything a detector could match, so
 * a golden line moves only when the VALUE's treatment moves.
 *
 * The last five put a LINE TERMINATOR straight after the token, because that is where dialects stop
 * agreeing on where a line ends. JavaScript's `.` refuses \n, \r, U+2028 and U+2029, and `$`
 * without the multiline flag only means end of input. .NET-derived engines exclude \n from `.` and
 * nothing else, so \r, U+2028 and U+2029 are ordinary characters a `.` will happily cross, and
 * their `$` also matches just before a trailing \n. Go's RE2 draws the line somewhere else again,
 * and treats U+2028 and U+2029 as neither space nor terminator. A token sitting immediately before
 * one of these is therefore the shortest case that can tell those engines apart.
 */
const TEMPLATES = [
  (v) => v,
  (v) => `value: ${v}`,
  (v) => `"${v}"`,
  (v) => `[info] connect from ${v} ok`,
  (v) => `field=${v};next=plain`,
  (v) => `trailing ${v}\n`,
  (v) => `trailing ${v}\r`,
  (v) => `trailing ${v}\r\n`,
  (v) => `trailing ${v}\u2028`,
  (v) => `trailing ${v}\u2029`,
  (v) => `split ${v}\u2028second half ${v}`,
];

/** Token values crossed with every template. `keep` means the line must survive byte-identical. */
const GROUPS = [
  {
    group: "ipv4-public",
    values: ["198.18.0.15", "198.19.200.7", "100.64.12.9"],
  },
  {
    group: "ipv4-private",
    values: ["10.0.1.50", "192.168.1.10", "172.16.5.4", "127.0.0.1"],
  },
  {
    group: "ipv4-cidr",
    values: ["10.0.0.0/8", "192.168.1.0/24", "198.18.0.0/15", "172.16.0.0/12"],
  },
  {
    group: "ipv4-range",
    values: ["10.0.1.50-10.0.1.60", "198.18.0.15-198.18.0.31"],
  },
  {
    group: "ipv6",
    values: [
      "fd12:3456:789a:0001:0000:0000:0000:0001",
      "fd12:3456::1",
      "fd12:3456:789a:1::abcd",
      "fd00::dead:beef",
      "fe80::1%eth0",
      "::ffff:10.0.1.50",
      "fd12:3456:789a:1:0:0:10.0.1.50",
    ],
  },
  {
    group: "email",
    values: ["alice@example.net", "bob.smith+tag@example.org", "svc_account@mail.example.net"],
  },
  {
    group: "mac",
    values: ["00:1A:2B:3C:4D:5E", "00-1a-2b-3c-4d-5e", "A0:B1:C2:D3:E4:F5"],
  },
  {
    group: "card-luhn-valid",
    values: [
      "4111111111111111",
      "4111 1111 1111 1111",
      "4111-1111-1111-1111",
      "5555555555554444",
      "378282246310005",
      "6011111111111117",
    ],
  },
  {
    // 16 digits is not a card number. A failed Luhn or an implausible prefix is an order id, an
    // asset tag or a correlation key, and eating those is how a redactor loses its readers.
    group: "card-luhn-invalid",
    keep: true,
    values: ["4111111111111112", "1234567890123456", "9999888877776666", "1234 5678 9012 3456"],
  },
  {
    group: "ssn",
    values: ["123-45-6789", "078-05-1120", "219-09-9999"],
  },
  {
    // Area 000/666/900+, group 00 and serial 0000 are never assigned, so these are not SSNs.
    group: "ssn-never-assigned",
    keep: true,
    values: ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-6789", "123-45-0000"],
  },
  {
    group: "phone-e164",
    values: ["+12025550147", "+442071838750"],
  },
  {
    group: "phone-nanp",
    values: ["(202) 555-0147", "202-555-0147", "(415)555-0198"],
  },
  {
    group: "phone-reserved",
    keep: true,
    values: ["+99900000001", "000-555-0101", "(000) 555-0102"],
  },
  {
    group: "username-path",
    values: [
      "C:\\Users\\jsmith\\AppData\\Local\\Temp\\a.log",
      "\\Users\\a.bhatt\\Desktop",
      "/home/jsmith/app.log",
      "/Users/jsmith/Library/Logs/app.log",
    ],
  },
  {
    group: "username-builtin",
    keep: true,
    values: [
      "C:\\Users\\Default\\NTUSER.DAT",
      "C:\\Users\\Public\\Documents\\a.txt",
      "C:\\Users\\Administrator\\a.log",
      "C:\\Users\\User00001\\AppData\\a.log",
    ],
  },
  {
    group: "sid",
    values: ["S-1-5-21-1234567890-987654321-1122334455-1001"],
  },
  {
    group: "sid-well-known",
    keep: true,
    values: ["S-1-5-18", "S-1-5-32-544", "S-1-5-21-0-0-0-1001"],
  },
  {
    group: "unc-host",
    values: ["\\\\FILESRV01\\share\\report.txt", "\\\\db01\\logs\\a.log"],
  },
  {
    group: "unc-not-a-host",
    keep: true,
    values: ["\\\\HOST0001\\share\\a.txt", "C:\\\\Windows\\\\CBS\\\\CBS.log", "\\\\?\\C:\\Windows"],
  },
  {
    group: "fqdn-internal",
    values: ["db01.corp.local", "printer.home.arpa", "wsus.example.lan", "mail.example.intranet"],
  },
  {
    group: "fqdn-public",
    keep: true,
    values: ["www.example.com", "api.example.net"],
  },
  {
    // JavaScript reads \d and \b as ASCII-only; .NET and Go read them wider unless told otherwise.
    // These runs LOOK like an SSN, a card and an address and must stay untouched on every dialect.
    group: "non-ascii-digits",
    keep: true,
    values: [
      "\uFF11\uFF12\uFF13-\uFF14\uFF15-\uFF16\uFF17\uFF18\uFF19",
      "\u0661\u0662\u0663-\u0664\u0665-\u0666\u0667\u0668\u0669",
      "\uFF14\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11\uFF11",
      "\uFF11\uFF10.\uFF10.\uFF11.\uFF15\uFF10",
    ],
  },
  {
    // An accented letter is not a word character in JavaScript, so \b holds against it; widen the
    // dialect and the same MAC stops matching. The pair below is what makes that visible.
    group: "non-ascii-adjacent",
    values: [
      "caf\u00e900:1A:2B:3C:4D:5E",
      "caf\u00e9 00:1A:2B:3C:4D:5E",
      "m\u00fcller@example.net",
      "na\u00efve 10.0.1.50 ok",
      "\u7528\u6237 \\\\FILESRV01\\share",
    ],
  },
  {
    // Placeholders an AI client writes when it pseudonymises before sending. They carry the
    // correlation the reader needs and must reach the reader intact.
    group: "placeholder",
    keep: true,
    values: ["<host-1>", "<user-2>", "<client-A>", "<ip-3>", "<ip-3>/24", "<user-2>@<host-1>"],
  },
  {
    // This engine's own output. Redaction has to be a fixed point or a value swept twice loses its
    // shape, so every fake here is one a detector's `safe` regex or validator recognises.
    group: "already-redacted",
    keep: true,
    values: [
      "redacted1@example.invalid",
      "192.0.2.5",
      "198.51.100.7",
      "2001:db8::1",
      "2001:db8:0:0:0:0:0:1",
      "::ffff:192.0.2.5",
      "00:00:5E:00:53:AA",
      "000-01-0001",
      "+99900000001",
      "4000000000000000",
      "S-1-5-21-0-0-0-1001",
      "HOST0001",
      "C:\\Users\\User00001\\a.log",
      "\\\\HOST0001\\share",
    ],
  },
  {
    // CREDENTIAL-SHAPED JSON KEYS. These carry no PII and both profiles here leave them alone, which
    // is the assertion: a PII pass must not start eating configuration. They sit in this corpus
    // because the credential corpus has no JSON object whose KEY names a credential, so the
    // credential engines have no graded case for the family at all; see CORPUS.md.
    group: "credential-json-key",
    keep: true,
    credential: true,
    values: [
      '{"password": "aGVsbG8td29ybGQ"}',
      '{"pwd": "aGVsbG8td29ybGQ"}',
      '{"secret": "aGVsbG8td29ybGQ"}',
      '{"token": "aGVsbG8td29ybGQ"}',
      '{"apikey": "aGVsbG8td29ybGQ"}',
      '{"api_key": "aGVsbG8td29ybGQ"}',
      '{"accountkey": "aGVsbG8td29ybGQ"}',
      '{"accesskey": "aGVsbG8td29ybGQ"}',
      '{"credential": "aGVsbG8td29ybGQ"}',
      '{"passphrase": "correct horse battery staple"}',
      '{"password": 1234}',
      '{"user": "jsmith", "password": "aGVsbG8td29ybGQ", "host": "<host-1>"}',
    ],
  },
  {
    // ASTRAL CHARACTERS, next to a token and inside one. Everything above U+FFFF is two UTF-16 code
    // units here, four UTF-8 bytes in Go, and one rune in Rust, so a span this engine reports at
    // offset 12 is not at offset 12 anywhere else. A port that carries the offsets rather than
    // recomputing them cuts a token in half, and the damage lands on the longer-first tiebreak in
    // particular, where two detectors claim overlapping spans and the wrong one has to lose.
    //
    // Adjacency also grades \b: an emoji and a supplementary-plane LETTER are both non-word to
    // JavaScript, so \b holds against either, and an engine that reads U+10400 as the letter it is
    // stops matching. The letter cases exist to separate that from the emoji case.
    group: "astral",
    values: [
      "\u{1F600}10.0.1.50",
      "10.0.1.50\u{1F600}",
      "\u{1F600} alice@example.net",
      "ali\u{1F600}ce@example.net",
      "\u{10400}00:1A:2B:3C:4D:5E",
      "00:1A:2B:3C:4D:5\u{1F600}E",
      "C:\\Users\\js\u{1F600}mith\\a.log",
      "C:\\Users\\\u{10400}mith\\a.log",
      "4111111111111\u{1F600}111",
      "\u{1F600}4111111111111111",
      "\u{1F600}123-45-6789",
      "\u{10400}db01.corp.local",
      "\\\\FILESRV01\u{1F600}\\share",
      "\u{1F600}\\\\FILESRV01\\share",
      // Overlapping claims: the IPv6 span contains the IPv4 span, so longer-first decides, and the
      // astral prefix moves every offset that decision is made on.
      "\u{1F600}::ffff:10.0.1.50",
      "\u{1F600}fd12:3456::10.0.1.50",
      "\u{1F600}fd12:3456:789a:1:0:0:10.0.1.50",
      "\u{1F600}fd12:3456:789a:1:0:0:10.0.1.50 and 10.0.1.60",
      "\u{1F600}10.0.1.50-10.0.1.60",
      "\u{1F600}10.0.0.0/8",
    ],
  },
];

/** Whole lines, emitted as written: several values at once, and mixtures with placeholders. */
const LITERALS = [
  {
    group: "mixed",
    values: [
      "user jsmith at 10.0.1.50 mailed alice@example.net from db01.corp.local",
      "C:\\Users\\jsmith\\a.log copied to \\\\FILESRV01\\share by S-1-5-21-1234567890-987654321-1122334455-1001",
      "NIC 00:1A:2B:3C:4D:5E leased 198.18.0.15 in 10.0.0.0/8 gateway fd12:3456::1",
      "order 1234567890123456 paid with 4111111111111111 by +12025550147",
      "session for <user-2> on <host-1> resolved to 10.0.1.50 (client <client-A>)",
      "backup of \\\\FILESRV01\\share to <host-1> failed for <user-2>\n",
      "ticket 000-12-3456 raised by alice@example.net about 198.18.0.15\n",
      "audit: 123-45-6789 and 123-45-0000 and 4111111111111111 and 4111111111111112",
      "\u{1F600} user js\u{1F600}mith at 10.0.1.50 mailed ali\u{1F600}ce@example.net \u{1F600}",
      "\u{10400} <host-1> \u{1F600} 10.0.1.50 <user-2> \u{10400} alice@example.net\n",
    ],
  },
  {
    group: "placeholder-only",
    keep: true,
    values: [
      "connection from <host-1> by <user-2> for <client-A> at <ip-3>",
      "\\\\<host-1>\\share\\a.txt",
      "C:\\Users\\<user-2>\\AppData\\Local\\a.log",
      "<client-A> reported <ip-3> unreachable from <host-1>\n",
    ],
  },
  {
    group: "empty-ish",
    keep: true,
    values: ["", " ", "\n", "no personal data on this line at all"],
  },
];

const out = [];
const seen = new Set();

function emit(caseName, message, keep, credential) {
  if (seen.has(message)) return; // a duplicate line grades nothing twice
  seen.add(message);
  const row = { case: caseName, message };
  // `keep` is a claim about the PII profiles: there is no personal data on this line. `credential`
  // narrows it, because a line can be free of PII and still carry a secret, and the union pass that
  // loads the credential detectors is REQUIRED to take that secret out.
  if (keep) row.keep = true;
  if (credential) row.credential = true;
  out.push(JSON.stringify(row));
}

for (const g of GROUPS) {
  for (const [vi, value] of g.values.entries()) {
    for (const [ti, tpl] of TEMPLATES.entries()) {
      emit(`${g.group}-${vi + 1}-t${ti + 1}`, tpl(value), g.keep === true, g.credential === true);
    }
  }
}
for (const g of LITERALS) {
  for (const [vi, value] of g.values.entries()) {
    emit(`${g.group}-${vi + 1}`, value, g.keep === true, g.credential === true);
  }
}

fs.writeFileSync(OUT, out.join("\n") + "\n", "utf8");
process.stdout.write(`wrote ${out.length} cases to ${OUT}\n`);
