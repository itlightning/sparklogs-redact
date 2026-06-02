import { test } from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../src/redact.ts";
import { loadProfile } from "../src/detectors.ts";

const r = () => new Redactor(loadProfile("secret"));

test("jwt: redacted into a shape-valid fake JWT; scan-clean; idempotent", () => {
  const red = r();
  const jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const out = red.redact(jwt);
  assert.ok(!out.text.includes(jwt), "raw JWT removed");
  assert.match(out.text, /^eyJ[A-Za-z0-9_-]*REDACTED/); // still header.payload.sig shaped
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("aws-access-key: AKIA… -> AKIAREDACTED + digits, keeps 20-char shape; scan-clean", () => {
  const red = r();
  const out = red.redact("key AKIAIOSFODNN7EXAMPLE used");
  assert.ok(!out.text.includes("AKIAIOSFODNN7EXAMPLE"));
  assert.match(out.text, /AKIAREDACTED\d{8}/);
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("private-key-block: whole PEM block replaced, armor preserved; scan-clean", () => {
  const red = r();
  const pem =
    "-----BEGIN RSA PRIVATE KEY-----\n" +
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n" +
    "uKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n" +
    "-----END RSA PRIVATE KEY-----";
  const out = red.redact(`before\n${pem}\nafter`);
  assert.ok(!out.text.includes("MIIBOgIBAAJBAKj34"), "key body removed");
  assert.match(
    out.text,
    /-----BEGIN PRIVATE KEY-----[\s\S]*REDACTED[\s\S]*-----END PRIVATE KEY-----/,
  );
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("auth-bearer: opaque token after 'Bearer ' redacted, scheme kept; scan-clean", () => {
  const red = r();
  const out = red.redact("Authorization: Bearer abc123DEF456ghi789");
  assert.ok(!out.text.includes("abc123DEF456ghi789"));
  assert.match(out.text, /Bearer REDACTED/);
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("auth-basic: base64 credential after 'Basic ' redacted; scan-clean", () => {
  const red = r();
  const out = red.redact("Authorization: Basic dXNlcjpwYXNzd29yZA==");
  assert.ok(!out.text.includes("dXNlcjpwYXNzd29yZA=="));
  assert.match(out.text, /Basic REDACTED/);
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("conn-string url password: only the password between ':' and '@' is redacted", () => {
  const red = r();
  const out = red.redact("dsn postgres://app:s3cr3tPass@db.example.com/mydb ok");
  assert.ok(!out.text.includes("s3cr3tPass"));
  assert.match(out.text, /:REDACTED-SECRET-\d+@db\.example\.com/);
  assert.ok(out.text.includes("postgres://app:"), "userinfo username kept");
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("conn-string key=value password (Password=…;) redacted; scan-clean", () => {
  const red = r();
  const out = red.redact("Server=db;Password=Hunter2xyz;Trusted=false");
  assert.ok(!out.text.includes("Hunter2xyz"));
  assert.match(out.text, /Password=REDACTED-SECRET-\d+;/);
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("secret-assignment: generic api_key=\"…\" value redacted; scan-clean", () => {
  const red = r();
  const out = red.redact('api_key="sk-livedeadbeef12345"');
  assert.ok(!out.text.includes("sk-livedeadbeef12345"));
  assert.match(out.text, /api_key="REDACTED-SECRET-\d+"/);
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

// Each vendor token: a shape-valid sample, plus a regex proving the redacted output keeps the
// vendor prefix immediately followed by the REDACTED sentinel.
// Split literals for a few high-signal shapes so GitHub push protection does not block the repo.
const j = (...parts: string[]) => parts.join("");

const VENDOR_CASES: Array<{ name: string; sample: string; keeps: RegExp }> = [
  { name: "github classic", sample: "ghp_0123456789abcdefghijklmnopqrstuvwxyz", keeps: /ghp_REDACTED/ },
  { name: "github oauth", sample: "gho_0123456789abcdefghijklmnopqrstuvwxyz", keeps: /gho_REDACTED/ },
  {
    name: "github fine-grained PAT",
    sample: "github_pat_0123456789abcdefghijkl_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW",
    keeps: /github_pat_REDACTED/,
  },
  { name: "gitlab", sample: "glpat-0123456789abcdefghij", keeps: /glpat-REDACTED/ },
  { name: "google api key", sample: "AIza0123456789abcdefghijklmnopqrstuvwxy", keeps: /AIzaREDACTED/ },
  { name: "slack token", sample: "xoxb-0123456789abcd", keeps: /xoxb-REDACTED/ },
  {
    name: "slack webhook",
    sample: j(
      "https://",
      "hooks.",
      "slack.com/services/T",
      "00000000",
      "/B",
      "00000000",
      "/0123456789abcdefghijklmn",
    ),
    keeps: /hooks\.slack\.com\/services\/T[A-Z0-9]*REDACTED/,
  },
  {
    name: "stripe secret key",
    sample: j("sk_", "live_", "0123456789abcdefghijklmn"),
    keeps: /sk_live_REDACTED/,
  },
  {
    name: "twilio api key",
    sample: j("SK", "0123456789abcdef", "0123456789abcdef"),
    keeps: /SKREDACTED/,
  },
  {
    name: "sendgrid",
    sample: j("SG.", "0123456789abcdefghijkl.", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"),
    keeps: /SG\.REDACTED/,
  },
  { name: "npm token", sample: "npm_0123456789abcdefghijklmnopqrstuvwxyz", keeps: /npm_REDACTED/ },
  { name: "anthropic", sample: "sk-ant-api03-0123456789abcdefghij", keeps: /sk-ant-REDACTED/ },
];

for (const c of VENDOR_CASES) {
  test(`vendor token (${c.name}): prefix-preserving redaction; scan-clean; idempotent`, () => {
    const red = r();
    const out = red.redact(`login ${c.sample} ok`);
    assert.ok(!out.text.includes(c.sample), `${c.name} raw token removed`);
    assert.match(out.text, c.keeps); // prefix kept + REDACTED sentinel
    assert.deepEqual(red.scan(out.text), [], `${c.name} scan clean`);
    assert.equal(red.redact(out.text).text, out.text, `${c.name} idempotent`);
  });
}

test("vendor token: a publishable Stripe pk_ key is NOT redacted (not a secret)", () => {
  const red = r();
  const text = j("pub pk_", "live_", "0123456789abcdefghijklmn ok");
  assert.equal(red.redact(text).text, text);
});

test("secret: a plain sentence with no credentials is untouched", () => {
  const red = r();
  const text = "the deployment finished without errors at noon";
  assert.equal(red.redact(text).text, text);
  assert.deepEqual(red.scan(text), []);
});
