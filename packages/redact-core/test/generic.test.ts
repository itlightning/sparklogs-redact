import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { loadProfile } from "../src/detectors.ts";

const r = () => new Redactor(loadProfile("generic"));

test("ipv4: redacts public + private into RFC 5737 doc ranges; scan-clean; idempotent", () => {
  const red = r();
  const input = "public 8.8.8.8 and private 10.1.2.3 here";
  const out = red.redact(input);
  assert.match(out.text, /192\.0\.2\.\d+/); // public  -> TEST-NET-1
  assert.match(out.text, /198\.51\.100\.\d+/); // private -> TEST-NET-2
  assert.ok(!out.text.includes("8.8.8.8"));
  assert.ok(!out.text.includes("10.1.2.3"));
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("ipv4: NOT matched when glued to '-' or '_' (likely part of an identifier)", () => {
  const red = r();
  const text = "build-10.0.0.1 and tag_192.168.1.1 stay put";
  assert.equal(red.redact(text).text, text);
});

test("ipv4-cidr: a '-'-glued address is still caught when followed by /n (CIDR signal)", () => {
  const red = r();
  const out = red.redact("route via gw-10.0.0.0/8 now");
  assert.match(out.text, /198\.51\.100\.\d+\/8/); // address redacted, /8 prefix kept
  assert.ok(!out.text.includes("10.0.0.0/8"));
});

test("ipv4: DOES redact a version-like dotted-quad in generic (accepted collision)", () => {
  const out = r().redact("version 10.0.0.0 build");
  assert.ok(!out.text.includes("10.0.0.0"));
});

test("ipv4-range: both endpoints of a glued A-B range redact; '-' preserved; scan-clean; idempotent", () => {
  const red = r();
  const out = red.redact("range 10.0.0.1-10.0.0.5 here");
  assert.ok(!out.text.includes("10.0.0.1"), "head redacted");
  assert.ok(!out.text.includes("10.0.0.5"), "tail redacted (range-tail rescue)");
  assert.match(out.text, /198\.51\.100\.\d+-198\.51\.100\.\d+/); // both ends, dash kept
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text); // tail `safe` carries -> idempotent
});

test("ipv4-range: an identifier ending in a digit does NOT rescue a dash-glued tail", () => {
  const red = r();
  // 'build2-' is not a dotted-quad, so the range-tail lookbehind fails and base blocks the '-'
  const text = "build2-10.0.0.5 stays";
  assert.equal(red.redact(text).text, text);
});

test("ipv4: a dotted-quad after '~~' (assembly-identity marker) is NOT matched", () => {
  const red = r();
  const text = "amd64~~10.0.1.2 keep";
  assert.equal(red.redact(text).text, text);
});

test("ipv4: a dotted-quad after a single '~' (field separator) IS matched", () => {
  const red = r();
  const out = red.redact("host~10.0.0.7 up");
  assert.ok(!out.text.includes("10.0.0.7"));
  assert.match(out.text, /198\.51\.100\.\d+/);
});

test("ipv6: redacts full / compressed / mapped / zoned forms; scan-clean; idempotent", () => {
  const red = r();
  const samples = [
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334", // full 8-group
    "fe80::1ff:fe23:4567:890a", // compressed
    "::1", // loopback (compressed)
    "::ffff:203.0.113.9", // IPv4-mapped
    "fe80::1%eth0", // with %zone id
  ];
  for (const s of samples) {
    const input = `addr ${s} end`;
    assert.ok(
      red.scan(input).some((h) => h.category === "ipv6"),
      `should detect ipv6 in ${s}`,
    );
    const out = red.redact(input);
    assert.notEqual(out.text, input, `should redact ${s}`);
    assert.match(out.text, /2001:db8|::ffff:192\.0\.2\./i);
    assert.deepEqual(red.scan(out.text), [], `scan clean for ${s}`);
    assert.equal(red.redact(out.text).text, out.text, `idempotent for ${s}`);
  }
});

test("ipv6: does NOT match bare '::' (avoids C++/std:: false positives)", () => {
  const red = r();
  const text = "std::vector<int> and foo::bar()";
  assert.equal(red.redact(text).text, text);
});

test("GUIDs/UUIDs are left intact (correlation IDs, not personal data)", () => {
  const red = r();
  const text = "request 550e8400-e29b-41d4-a716-446655440000 ok";
  assert.equal(red.redact(text).text, text);
});

test("credit-card: redacts a Luhn-valid number, leaves a Luhn-invalid lookalike", () => {
  const red = r();
  const valid = "4111 1111 1111 1111"; // Visa test number (Luhn-valid)
  const invalid = "4111 1111 1111 1112"; // same shape, fails Luhn
  const out = red.redact(`paid ${valid} ref ${invalid}`);
  assert.ok(!out.text.includes(valid), "valid card redacted");
  assert.ok(out.text.includes(invalid), "invalid lookalike untouched");
  assert.deepEqual(red.scan(out.text), []);
});

test("credit-card: ignores long numeric IDs that fail the brand/Luhn check", () => {
  const red = r();
  const text = "trace 1234567890123456 done"; // 16 digits, MII 1 -> not a card
  assert.equal(red.redact(text).text, text);
});

test("ssn: redacts a structurally valid SSN, leaves an invalid-area one", () => {
  const red = r();
  const out = red.redact("ssn 123-45-6789 and 000-12-3456 here");
  assert.ok(!out.text.includes("123-45-6789"));
  assert.ok(out.text.includes("000-12-3456")); // area 000 is never a real SSN
  assert.deepEqual(red.scan(out.text), []);
});

test("phone: redacts E.164 and NANP forms; leaves a bare digit run", () => {
  const red = r();
  const out = red.redact("call +14155550123 or (415) 555-0123, id 4155550123");
  assert.ok(!out.text.includes("+14155550123"));
  assert.ok(!out.text.includes("(415) 555-0123"));
  assert.ok(out.text.includes("4155550123")); // bare 10-digit id is NOT a phone match
  assert.deepEqual(red.scan(out.text), []);
});
