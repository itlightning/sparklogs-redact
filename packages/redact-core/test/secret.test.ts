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

test("http-auth: opaque token after an Authorization Bearer header; scheme kept; scan-clean", () => {
  const red = r();
  const out = red.redact("Authorization: Bearer abc123DEF456ghi789");
  assert.ok(!out.text.includes("abc123DEF456ghi789"));
  assert.match(out.text, /Bearer REDACTED/);
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("http-auth: base64 credential after an Authorization Basic header; scan-clean", () => {
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

// The broad `key = value` detector that used to sit here is gone. It anchored on a bare word with
// no sigil and a whitespace-tolerant separator, which made it the source of every remaining false
// positive in the corpus: it redacted `publicKeyToken=`, it redacted `token=` inside the sentence
// "The token=X was rejected by the API", and its `\s*` separator crossed a LINE BREAK and ate the
// first token of the next line. The precise detectors above cover the same credentials.
test("an uppercase environment-style assignment is still redacted", () => {
  const red = r();
  const out = red.redact("export API_KEY=abc123def456");
  assert.equal(out.text, "export API_KEY=REDACTED-SECRET-1");
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("a credential word in a sentence is not an assignment", () => {
  const red = r();
  assert.equal(
    red.redact("The token=SYNTHTOK00 was rejected by the API").text,
    "The token=SYNTHTOK00 was rejected by the API",
  );
});

test("no detector separator crosses a line break", () => {
  const red = r();
  const text = "Installer property dump:\nTOKEN=\nSITEID=41207 recorded for acme";
  assert.equal(red.redact(text).text, text);
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

// Connection-string credential matrix. All SYNTHETIC: the shapes are the published vendor forms, the
// credentials are invented. Each row asserts three things at once: the credential is gone, the
// surroundings survive byte for byte (over-redaction is a product failure of its own), and the
// redacted text is scan-clean and idempotent.
const CONN_CASES: Array<{ name: string; text: string; secret: string; keeps: string[] }> = [
  {
    name: "sql server oledb",
    text: "Provider=SQLOLEDB;Data Source=SQLSRV01;Initial Catalog=BillingDb;User ID=svc_billing;Password=Wint3rStorm;",
    secret: "Wint3rStorm",
    keeps: ["Provider=SQLOLEDB", "Initial Catalog=BillingDb", "User ID=svc_billing", "Password=", ";"],
  },
  {
    name: "sql server odbc",
    text: "Driver={ODBC Driver 17 for SQL Server};Server=tcp:sqlsrv01,1433;Database=BillingDb;UID=svc_billing;PWD=Wint3rStorm;Encrypt=yes",
    secret: "Wint3rStorm",
    keeps: ["UID=svc_billing", ";Encrypt=yes"],
  },
  {
    name: "sql server sqlclient, space-bearing password",
    text: "Server=sqlsrv01;Database=BillingDb;User Id=svc_billing;Password=P@ss w0rd!;MultipleActiveResultSets=True",
    secret: "P@ss w0rd!",
    keeps: ["User Id=svc_billing", ";MultipleActiveResultSets=True"],
  },
  {
    name: "sqlclient, space-bearing password at end of line",
    text: "Server=sqlsrv01;Uid=svc;Password=P@ss w0rd!",
    secret: "P@ss w0rd!",
    keeps: ["Server=sqlsrv01", "Uid=svc"],
  },
  {
    name: "quoted value containing a semicolon",
    text: 'Server=sqlsrv01;Database=BillingDb;Uid=svc;Password="quoted;pw";Encrypt=true',
    secret: "quoted;pw",
    keeps: ["Uid=svc", ";Encrypt=true"],
  },
  {
    name: "unquoted value containing semicolons",
    text: "Server=sqlsrv01;Uid=svc;Password=pw;with;semis;Encrypt=true",
    secret: "pw;with;semis",
    keeps: ["Server=sqlsrv01", ";Encrypt=true"],
  },
  {
    name: "mysql",
    text: "server=mysql01;port=3306;database=shopdb;user=appuser;password=Tr0ub4dor&3;SslMode=Required",
    secret: "Tr0ub4dor&3",
    keeps: ["user=appuser", ";SslMode=Required"],
  },
  {
    name: "postgresql keyword form",
    text: "Host=pg01;Port=5432;Database=analytics;Username=reader;Password=corr3ct-h0rse;Pooling=true",
    secret: "corr3ct-h0rse",
    keeps: ["Username=reader", ";Pooling=true"],
  },
  {
    name: "oracle odp.net",
    text: "Data Source=ORCL;User Id=hr;Password=hrPa55;Enlist=false",
    secret: "hrPa55",
    keeps: ["Data Source=ORCL", ";Enlist=false"],
  },
  {
    name: "access jet oledb",
    text: "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=D:\\Share\\Ledger.mdb;Jet OLEDB:Database Password=Led&ger1;",
    secret: "Led&ger1",
    keeps: ["Data Source=D:\\Share\\Ledger.mdb", "Database Password="],
  },
  {
    name: "azure storage account key",
    text: "DefaultEndpointsProtocol=https;AccountName=contosologs;AccountKey=Yzk4NmJhZmZlZTAxMjM0NTY3ODlhYmNkZWY=;EndpointSuffix=core.windows.net",
    secret: "Yzk4NmJhZmZlZTAxMjM0NTY3ODlhYmNkZWY=",
    keeps: ["AccountName=contosologs", ";EndpointSuffix=core.windows.net"],
  },
  {
    name: "azure shared access signature",
    text: "BlobEndpoint=https://contosologs.blob.core.windows.net/;SharedAccessSignature=sv=2021-06-08&ss=b&sig=aBcDeFg;",
    secret: "sv=2021-06-08&ss=b&sig=aBcDeFg",
    keeps: ["BlobEndpoint=https://contosologs.blob.core.windows.net/"],
  },
];

for (const c of CONN_CASES) {
  test(`conn-string-password: ${c.name}`, () => {
    const red = r();
    const out = red.redact(c.text);
    assert.ok(!out.text.includes(c.secret), `${c.name}: credential removed`);
    for (const keep of c.keeps) {
      assert.ok(out.text.includes(keep), `${c.name}: kept ${keep}`);
    }
    assert.deepEqual(red.scan(out.text), [], `${c.name}: scan clean`);
    assert.equal(red.redact(out.text).text, out.text, `${c.name}: idempotent`);
  });
}

// URL userinfo passwords: the username, host, port and path are diagnostic and must survive.
const URL_CASES: Array<{ name: string; text: string; secret: string; keeps: string[] }> = [
  {
    name: "postgresql uri",
    text: "postgresql://reader:corr3ct-h0rse@pg01:5432/analytics",
    secret: "corr3ct-h0rse",
    keeps: ["postgresql://reader:", "@pg01:5432/analytics"],
  },
  {
    name: "mongodb srv",
    text: "mongodb+srv://appuser:M0ng0-Pa55@cluster0.example.net/shopdb?retryWrites=true",
    secret: "M0ng0-Pa55",
    keeps: ["mongodb+srv://appuser:", "@cluster0.example.net/shopdb?retryWrites=true"],
  },
  {
    name: "amqp uri",
    text: "amqp://svc_queue:Rabb1t-Pa55@rabbit01:5672/prod",
    secret: "Rabb1t-Pa55",
    keeps: ["amqp://svc_queue:", "@rabbit01:5672/prod"],
  },
];

for (const c of URL_CASES) {
  test(`conn-string-url-password: ${c.name}`, () => {
    const red = r();
    const out = red.redact(c.text);
    assert.ok(!out.text.includes(c.secret), `${c.name}: credential removed`);
    for (const keep of c.keeps) {
      assert.ok(out.text.includes(keep), `${c.name}: kept ${keep}`);
    }
    assert.deepEqual(red.scan(out.text), [], `${c.name}: scan clean`);
    assert.equal(red.redact(out.text).text, out.text, `${c.name}: idempotent`);
  });
}

test("conn-string: NEGATIVE PROOF, a credential-free connection string is untouched", () => {
  const red = r();
  const text = "Provider=SQLOLEDB;Data Source=SQLSRV01;Initial Catalog=BillingDb;Integrated Security=SSPI;";
  assert.equal(red.redact(text).text, text);
  assert.deepEqual(red.scan(text), []);
});

test("conn-string: a host:port URL with no userinfo is untouched", () => {
  const red = r();
  const text = "Health probe https://contoso.example.com:8443/api/health returned 503";
  assert.equal(red.redact(text).text, text);
});

test("conn-string: bare password= in prose stays whitespace-terminated", () => {
  const red = r();
  const out = red.redact("Vault sync failed: password=hunter2 and then more prose here");
  assert.ok(!out.text.includes("hunter2"));
  assert.ok(out.text.endsWith(" and then more prose here"), "prose after the credential survives");
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

test("conn-string: the word password in ordinary prose is not an assignment", () => {
  const red = r();
  const text = "The user password expired for account svc_billing";
  assert.equal(red.redact(text).text, text);
});

// PREFIXED CREDENTIAL KEYS. `\b` does not fire between a lowercase letter and an uppercase one, so a
// key alternation anchored on it alone can never start mid-identifier and `SecretAccessKey=` slipped
// through. That is the SECRET half of an AWS key pair and a common application-log shape, so the gap
// leaked a live credential. All SYNTHETIC: invented credentials, published key shapes.
const PREFIXED_CASES: Array<{ name: string; text: string; secret: string; keeps: string[] }> = [
  {
    name: "aws secret access key",
    text: "Upload failed. Region=us-east-1;SecretAccessKey=wJalrXUtnFEMI-K7MDENG-bPxRfiCY;Bucket=contoso-archive",
    secret: "wJalrXUtnFEMI-K7MDENG-bPxRfiCY",
    keeps: ["Region=us-east-1", "SecretAccessKey=", ";Bucket=contoso-archive"],
  },
  {
    name: "aws secret access key, vendor-prefixed",
    text: "Upload failed. Region=us-east-1;AwsSecretAccessKey=wJalrXUtnFEMI-K7MDENG-bPxRfiCY;Bucket=contoso-archive",
    secret: "wJalrXUtnFEMI-K7MDENG-bPxRfiCY",
    keeps: ["Region=us-east-1", "AwsSecretAccessKey=", ";Bucket=contoso-archive"],
  },
  {
    name: "unprefixed keys still match",
    text: "DefaultEndpointsProtocol=https;AccountName=contosologs;AccountKey=Yzk4NmJhZmZlZTAxMjM0NTY3ODlhYmNkZWY=;EndpointSuffix=core.windows.net",
    secret: "Yzk4NmJhZmZlZTAxMjM0NTY3ODlhYmNkZWY=",
    keeps: ["AccountName=contosologs", ";EndpointSuffix=core.windows.net"],
  },
];

for (const c of PREFIXED_CASES) {
  test(`conn-string-password prefix: ${c.name}`, () => {
    const red = r();
    const out = red.redact(c.text);
    assert.ok(!out.text.includes(c.secret), `${c.name}: credential removed`);
    for (const keep of c.keeps) {
      assert.ok(out.text.includes(keep), `${c.name}: kept ${keep}`);
    }
    assert.deepEqual(red.scan(out.text), [], `${c.name}: scan clean`);
    assert.equal(red.redact(out.text).text, out.text, `${c.name}: idempotent`);
  });
}

// The NEGATIVE PROOF for the identifier prefix, and the reason it is bounded to `[A-Za-z_]*`
// immediately before the `=`. A broad key match is how over-redaction starts, so a key that merely
// CONTAINS a credential word, but is not a credential key, must survive byte for byte.
const PREFIX_NEGATIVES: Array<{ name: string; text: string }> = [
  { name: "policy name", text: "Policy load failed. MyPasswordPolicy=strict;Scope=domain" },
  { name: "expiry day count", text: "PasswordExpiryDays=90 for account svc_billing" },
  { name: "change timestamp", text: "Audit: LastPasswordChange=2026-08-01T09:00:00Z;Actor=svc_billing" },
  { name: "plain user key", text: "Server=sqlsrv01;user=bob;Encrypt=true" },
];

for (const c of PREFIX_NEGATIVES) {
  test(`conn-string-password prefix negative: ${c.name}`, () => {
    const red = r();
    assert.equal(red.redact(c.text).text, c.text, `${c.name}: untouched`);
    assert.deepEqual(red.scan(c.text), [], `${c.name}: scan clean`);
  });
}

// `accesskeyid` is the PUBLIC half of an AWS key pair, so the connection-string detector must not
// claim it. The value is still redacted, but by `aws-access-key`, which keeps the AKIA shape; that
// distinct replacement is what proves which detector fired.
test("conn-string-password prefix negative: accesskeyid is not a credential key", () => {
  const red = r();
  const out = red.redact("Upload failed. accesskeyid=AKIAIOSFODNN7EXAMPLE;Region=us-east-1;Bucket=contoso-archive");
  assert.match(out.text, /accesskeyid=AKIAREDACTED\d{8};Region=us-east-1;Bucket=contoso-archive$/);
  assert.deepEqual(red.scan(out.text), []);
  assert.equal(red.redact(out.text).text, out.text);
});

// JSON CREDENTIAL VALUES. Both connection-string detectors anchor on `=`, and a JSON body has none,
// so a REST or RPC result body carrying a session credential passed through untouched. The key must
// END with the credential word, so the closing quote sits immediately after it and a key that merely
// CONTAINS one keeps its value. All SYNTHETIC: invented credentials, invented field names.
const JSON_CRED_CASES: Array<{ name: string; text: string; secret: string; keeps: string[] }> = [
  {
    name: "session credential in a remote-assist result body",
    text: '{"sessionpassword":"{225FD96D-A68C-4F1E-9B22-000000000000}","user":"bob"}',
    secret: "225FD96D-A68C-4F1E-9B22-000000000000",
    keeps: ['"sessionpassword":"', '"user":"bob"'],
  },
  {
    name: "bare password key",
    text: '{"password":"Wint3r!Storm","user":"bob"}',
    secret: "Wint3r!Storm",
    keeps: ['"password":"', '"user":"bob"'],
  },
  {
    name: "camel-case key with a space after the colon",
    text: '{"apiToken": "contoso.abc.def","user":"bob"}',
    secret: "contoso.abc.def",
    keeps: ['"apiToken": "', '"user":"bob"'],
  },
  {
    name: "underscore-prefixed key",
    text: '{"client_secret":"s3cr3tvalue","client_id":"contoso-app"}',
    secret: "s3cr3tvalue",
    keeps: ['"client_secret":"', '"client_id":"contoso-app"'],
  },
  {
    name: "several credential members in one body",
    text: '{"api_key":"k-aaaaaa","accesskey":"k-bbbbbb","passphrase":"open sesame"}',
    secret: "open sesame",
    keeps: ['"api_key":"', '"accesskey":"', '"passphrase":"'],
  },
  {
    name: "escaped quote inside the value does not end the match early",
    text: '{"pwd":"ab\\"cd","user":"bob"}',
    secret: "ab",
    keeps: ['"pwd":"', '"user":"bob"'],
  },
];

for (const c of JSON_CRED_CASES) {
  test(`json-credential-value: ${c.name}`, () => {
    const red = r();
    const out = red.redact(c.text);
    assert.ok(!out.text.includes(c.secret), `${c.name}: credential removed`);
    for (const keep of c.keeps) {
      assert.ok(out.text.includes(keep), `${c.name}: kept ${keep}`);
    }
    assert.doesNotThrow(() => JSON.parse(out.text), `${c.name}: still parseable JSON`);
    assert.deepEqual(red.scan(out.text), [], `${c.name}: scan clean`);
    assert.equal(red.redact(out.text).text, out.text, `${c.name}: idempotent`);
  });
}

// The NEGATIVE PROOF, and the reason the key must END with the credential word. A key that merely
// CONTAINS one is a setting name, a counter or a date, and it carries the diagnostic value of the
// line. `accesskeyid` is the PUBLIC half of an AWS key pair, an identifier rather than a secret.
const JSON_CRED_NEGATIVES = [
  '{"passwordExpiryDays":"90"}',
  '{"passwordPolicy":"strict"}',
  '{"tokenCount":"5"}',
  '{"user":"bob"}',
  '{"lastPasswordChange":"2026-08-22"}',
  '{"accesskeyid":"contoso-public-id","secretRotationDays":"30"}',
];

for (const text of JSON_CRED_NEGATIVES) {
  test(`json-credential-value negative: ${text}`, () => {
    assert.equal(r().redact(text).text, text);
  });
}

// --- The key=value credential, after the rewrite that merged the connection-string and prose forms
// into one detector. Each positive below states the WHOLE expected line, so an edit that widens the
// value by one character fails here rather than passing a "the secret is gone" assertion.

test("conn-string url password: an unbounded username still yields its password", () => {
  // A ceiling on the username is a leak: past it the whole match fails and the password ships.
  const red = r();
  const user = "u".repeat(80);
  const out = red.redact(`dsn postgres://${user}:s3cr3tPass@db.example.com/mydb`);
  assert.ok(!out.text.includes("s3cr3tPass"));
  assert.match(out.text, new RegExp(`postgres://${user}:REDACTED-SECRET-\\d+@db\\.example\\.com`));
  assert.equal(red.redact(out.text).text, out.text);
});

test("conn-string password: a long neighbour key is still a key", () => {
  // The neighbour is what the detector exists to preserve; a ceiling on the key run kills it.
  const red = r();
  const out = red.redact("Server=db01;Password=Hunter2xyz;ApplicationIntentForReporting=ReadOnly");
  assert.equal(
    out.text,
    "Server=db01;Password=REDACTED-SECRET-1;ApplicationIntentForReporting=ReadOnly",
  );
});

test("conn-string password: a non-ASCII neighbour key is still a key", () => {
  // `\w` is ASCII-only in JavaScript, so this is the case that silently over-redacts without the
  // Unicode property classes: the neighbour stops looking like a key and the value eats the line.
  const red = r();
  const out = red.redact("Password=Hunter2xyz;Kééé=keepme");
  assert.equal(out.text, "Password=REDACTED-SECRET-1;Kééé=keepme");
});

test("conn-string password: a doubled quote does not end the value early", () => {
  const red = r();
  const out = red.redact('--password="a""b" --site Acme');
  assert.equal(out.text, "--password=REDACTED-SECRET-1 --site Acme");
});

test("conn-string password: a value opening with a doubled quote goes whole", () => {
  // The partial-redaction shape: the empty quote pair is a valid shorter run, so without the
  // delimiter requirement after the closing quote the placeholder lands and the credential ships.
  const red = r();
  const out = red.redact('Password=""Hunter2xyz""";Server=db01');
  assert.ok(!out.text.includes("Hunter2xyz"));
  assert.equal(out.text, "Password=REDACTED-SECRET-1;Server=db01");
});

test("conn-string password: an unterminated quote eats to end of line", () => {
  const red = r();
  const out = red.redact('--password="ab --site Acme');
  assert.ok(!out.text.includes("ab --site"));
  assert.equal(out.text, "--password=REDACTED-SECRET-1");
});

test("conn-string password: a bare value keeps its apostrophe and stops at whitespace", () => {
  const red = r();
  const out = red.redact("password=don't --site Acme");
  assert.ok(!out.text.includes("don't"));
  assert.equal(out.text, "password=REDACTED-SECRET-1 --site Acme");
});

test("conn-string password: the value stops before the next command-line flag", () => {
  // `;word=` inside a quoted argument makes the whole line look like a connection string, so
  // without the flag guard the value would run across the rest of the command.
  const red = r();
  const out = red.redact('azcopy --account-key=Hunter2xyz; --metadata "env=prod;tier=1"');
  assert.equal(out.text, 'azcopy --account-key=REDACTED-SECRET-1 --metadata "env=prod;tier=1"');
});

test("conn-string password: the AWS secret half is caught, the public half is not", () => {
  const red = r();
  const out = red.redact("AwsSecretAccessKey=Hunter2xyz Region=us-east-1");
  assert.equal(out.text, "AwsSecretAccessKey=REDACTED-SECRET-1 Region=us-east-1");
});

// The negative half: a key that merely CONTAINS a credential word names a setting, a counter or a
// date, and `accesskeyid` is the public half of an AWS key pair.
const CONN_KV_NEGATIVES = [
  "PasswordExpiryDays=90 and MyPasswordPolicy=strict",
  "accesskeyid=contoso-public-id is the public half",
  "The password field was empty for user alice",
  "LastPasswordChange=2026-08-22",
];

for (const text of CONN_KV_NEGATIVES) {
  test(`conn-string password negative: ${text}`, () => {
    assert.equal(r().redact(text).text, text);
  });
}

// --- Vendor token prefixes. The body length is a floor, not a width: a vendor mints at whatever
// size it likes, and an exact width plus a trailing word boundary drops every other size and every
// base64url body ending in a character that has no boundary after it.

const VENDOR_POSITIVES: [string, string, RegExp][] = [
  ["gitlab-pat, wider than the classic 20", "glpat-" + "A".repeat(28), /^glpat-REDACTED\d+0*$/],
  ["gitlab-pat, body ending in a dash", "glpat-" + "A".repeat(19) + "-", /^glpat-REDACTED\d+0*$/],
  ["github-token, wider than the classic 36", "ghp_" + "B".repeat(40), /^ghp_REDACTED\d+0*$/],
  ["google-api-key, wider than 35", "AIza" + "C".repeat(40), /^AIzaREDACTED\d+0*$/],
  ["npm-token, narrower than 36", "npm_" + "D".repeat(30), /^npm_REDACTED\d+0*$/],
  ["slack app-configuration token", "xoxe-" + "E".repeat(20), /^xoxe-REDACTED\d+0*$/],
  ["sparklogs ingest key", "sl_us_" + "F".repeat(43), /^sl_us_REDACTED\d+0*$/],
  ["sparklogs agent key", "slk_" + "a".repeat(64), /^slk_REDACTED\d+0*$/],
  [
    "sparklogs refresh token",
    "slr_" + "G".repeat(43) + "." + "H".repeat(43),
    /^slr_REDACTED\d+0*\.REDACTED\d+0*$/,
  ],
];

for (const [label, token, fake] of VENDOR_POSITIVES) {
  test(`vendor token: ${label}`, () => {
    const red = r();
    const out = red.redact(`Webhook rejected: token ${token} for client acme`);
    assert.ok(!out.text.includes(token), "raw token removed");
    const replaced = out.text.slice("Webhook rejected: token ".length).split(" ")[0];
    assert.match(replaced, fake, "fake keeps the vendor prefix");
    assert.ok(out.text.endsWith(" for client acme"), "the neighbour survives");
    assert.equal(red.redact(out.text).text, out.text);
  });
}

// The prefix ALONE is a word people write in prose and in paths, and none of these carries a body.
const VENDOR_NEGATIVES = [
  "The ghp_ prefix identifies a GitHub personal access token for acme",
  "Path C:\\Users\\bob\\AppData\\Local\\npm_cache\\index.json not found",
  "Region sl_us_east was selected for the workspace",
  "glpat-short is not a token",
];

for (const text of VENDOR_NEGATIVES) {
  test(`vendor token negative: ${text}`, () => {
    assert.equal(r().redact(text).text, text);
  });
}

// --- Tool-anchored command-line credentials. Each family carries its negatives, because a tool
// anchor can reach across a command separator, a flag anchor can claim the next argument, and a
// scheme word can fire inside ordinary prose.

const TOOL_CASES: [string, string, string][] = [
  [
    "msi public property",
    "msiexec /i C:\\pkg\\rmm-agent.msi /qn TOKEN=SYNTHTOKEN0000 SITE=Acme",
    "msiexec /i C:\\pkg\\rmm-agent.msi /qn TOKEN=REDACTED-SECRET-1 SITE=Acme",
  ],
  [
    "msi property inside a /v wrapper, quotes escaped",
    'setup.exe /S /v"/qn AUTHKEY=SYNTHAUTH0000"',
    'setup.exe /S /v"/qn AUTHKEY=REDACTED-SECRET-1"',
  ],
  [
    "proxy-authorization header, NTLM scheme",
    "Proxy-Authorization: NTLM SYNTHNTLM0000 rejected by proxy",
    "Proxy-Authorization: NTLM REDACTEDTOKEN1 rejected by proxy",
  ],
  [
    "authorization inside a JSON header object",
    '{"Authorization":"ApiKey SYNTHKEY0000","Accept":"application/json"}',
    '{"Authorization":"ApiKey REDACTEDTOKEN1","Accept":"application/json"}',
  ],
  [
    "putty -pw",
    "plink -l bob -pw SYNTHPW0000 host01 uptime",
    "plink -l bob -pw REDACTED-SECRET-1 host01 uptime",
  ],
  [
    "sqlcmd uppercase -P",
    'sqlcmd -S db01 -U sa -P SYNTHSQL0000 -Q "SELECT 1"',
    'sqlcmd -S db01 -U sa -P REDACTED-SECRET-1 -Q "SELECT 1"',
  ],
  [
    "sigil-prefixed word flag, equals form",
    "tool --pass=SYNTHPASS000 --site Acme",
    "tool --pass=REDACTED-SECRET-1 --site Acme",
  ],
  [
    "sigil-prefixed word flag, colon form",
    "tool /pwd:SYNTHPWD0000 --site Acme",
    "tool /pwd:REDACTED-SECRET-1 --site Acme",
  ],
];

for (const [label, input, expected] of TOOL_CASES) {
  test(`command-line credential: ${label}`, () => {
    const red = r();
    const out = red.redact(input);
    assert.equal(out.text, expected);
    assert.equal(red.redact(out.text).text, out.text);
  });
}

// The other half of each family's contract. A path, a statistics flag, a header name in a sentence
// and a prompt placeholder all carry diagnostic value and none of them is a credential.
const TOOL_NEGATIVES = [
  "msiexec /i a.msi /qn TOKENFILE=C:\\cfg\\t.txt CUSTOMERID=41207",
  "msiexec /i a.msi /qn TransformSecretName=x TENANT=acme",
  "msiexec /i a.msi /qn SiteKey=quietvalue TENANT=acme",
  "401 Unauthorized: the Authorization header was missing from req-9",
  "Access-Control-Allow-Headers: Authorization, Content-Type, X-Request-Id",
  "Rotation note: bearer slk_abc is one character short",
  "pscp -pwfile C:\\keys\\ssh.txt src host:/dst",
  'sqlcmd -S db01 -p -Q "SELECT 1"',
  "tool -tokenfile=C:\\cfg\\t.txt --site Acme",
  "net use Z: \\\\fs01\\share /user:acme\\bob *",
];

for (const text of TOOL_NEGATIVES) {
  test(`command-line credential negative: ${text}`, () => {
    assert.equal(r().redact(text).text, text);
  });
}

// --- PowerShell, the registry and curl. These families need real adaptation rather than a
// transcription: a zero-width anchor cannot absorb the text between an optional hop and its value,
// and a value whose quoting must survive has to be matched from the inside.

const PS_CASES: [string, string, string][] = [
  [
    "securestring positional argument",
    'ConvertTo-SecureString "SYNTHPW0000" -AsPlainText -Force',
    "ConvertTo-SecureString REDACTED-SECRET-1 -AsPlainText -Force",
  ],
  [
    "securestring named -String argument",
    'ConvertTo-SecureString -String "SYNTHPW0001" -AsPlainText -Force',
    "ConvertTo-SecureString -String REDACTED-SECRET-1 -AsPlainText -Force",
  ],
  [
    "securestring: only the named value, not the word after the cmdlet",
    'Use ConvertTo-SecureString instead of New-Object -String "SYNTHPW0002"',
    "Use ConvertTo-SecureString instead of New-Object -String REDACTED-SECRET-1",
  ],
  [
    "securestring by pipe",
    '"SYNTHPW0003" | ConvertTo-SecureString -AsPlainText -Force',
    "REDACTED-SECRET-1 | ConvertTo-SecureString -AsPlainText -Force",
  ],
  [
    "named secret parameter keeps its quotes",
    'Set-Thing -Password "Sy nth Pw" -Site Acme',
    'Set-Thing -Password "REDACTED-SECRET-1" -Site Acme',
  ],
  [
    "named secret parameter, single-quoted",
    "Set-Thing -Password 'Sy nth Pw' -Site Acme",
    "Set-Thing -Password 'REDACTED-SECRET-1' -Site Acme",
  ],
  [
    "named secret parameter, doubled quote inside",
    'Set-Thing -Password "a""b" -Site Acme',
    'Set-Thing -Password "REDACTED-SECRET-1" -Site Acme',
  ],
  [
    "reg add, value name ending in a credential word",
    "reg add HKLM\\SOFTWARE\\Acme /v DefaultPassword /t REG_SZ /d SYNTHREG0000 /f",
    "reg add HKLM\\SOFTWARE\\Acme /v DefaultPassword /t REG_SZ /d REDACTED-SECRET-1 /f",
  ],
  [
    "curl -u, bare password, username kept",
    "curl -u alice:SYNTHCURL000 https://api.example.com/v1",
    "curl -u alice:REDACTED-SECRET-1 https://api.example.com/v1",
  ],
  [
    "curl -u, whole pair quoted, quotes and username kept",
    'curl -u "alice:SYNTH CURL 1" https://api.example.com/v1',
    'curl -u "alice:REDACTED-SECRET-1" https://api.example.com/v1',
  ],
  [
    "curl --user long form",
    "curl --user bob:SYNTHCURL002 -X POST https://api.example.com",
    "curl --user bob:REDACTED-SECRET-1 -X POST https://api.example.com",
  ],
];

for (const [label, input, expected] of PS_CASES) {
  test(`powershell, registry and curl: ${label}`, () => {
    const red = r();
    const out = red.redact(input);
    assert.equal(out.text, expected);
    assert.equal(red.redact(out.text).text, out.text);
  });
}

// A variable, an expression, a boolean policy toggle, a port number and a curl with no credential
// at all. Each is the shape that a slightly greedier version of one of the above would eat.
const PS_NEGATIVES = [
  "$sec = ConvertTo-SecureString $env:PW -AsPlainText -Force",
  "$sec = ConvertTo-SecureString (Get-Content C:\\cfg\\pw.txt) -AsPlainText",
  "reg add HKLM\\SOFTWARE\\Acme /v DisableChangePassword /t REG_DWORD /d 1 /f",
  "reg add HKLM\\SOFTWARE\\Acme /v ProxyPort /t REG_DWORD /d 8080 /f",
  "reg add HKLM\\SOFTWARE\\Acme /v ProxyServer /t REG_SZ /d proxy.acme.example /f",
  "curl -s https://api.example.com/v1/users -o out.json",
];

for (const text of PS_NEGATIVES) {
  test(`powershell, registry and curl negative: ${text}`, () => {
    assert.equal(r().redact(text).text, text);
  });
}

// --- The positional families. No flag names the credential, so the anchor is the tool plus the
// argument order in front of it, and every value branch carries its own terminator: sharing one
// lets a quoted run that cannot close shorten itself and leave half the password on the line.

const POSITIONAL_CASES: [string, string, string][] = [
  ["net user", "net user bob SYNTHNET0000", "net user bob REDACTED-SECRET-1"],
  [
    "net user with switches after the password",
    "net user bob SYNTHNET0001 /add /domain",
    "net user bob REDACTED-SECRET-1 /add /domain",
  ],
  [
    "net user, quoted password with spaces",
    'net user bob "Sy nth Net 2" /add',
    "net user bob REDACTED-SECRET-1 /add",
  ],
  [
    "net user, command chained after the password",
    "net user bob SYNTHNET0003 && echo done",
    "net user bob REDACTED-SECRET-1 && echo done",
  ],
  [
    "net user, output redirected after the password",
    "net user bob SYNTHNET0004 > C:\\log.txt",
    "net user bob REDACTED-SECRET-1 > C:\\log.txt",
  ],
  [
    "net use, UNC share and /user option kept",
    "net use Z: \\\\fs01\\backups SYNTHUSE0000 /user:acme\\bob",
    "net use Z: \\\\fs01\\backups REDACTED-SECRET-1 /user:acme\\bob",
  ],
  [
    "bitsadmin, job target scheme and user kept",
    "bitsadmin /SetCredentials Job SERVER NTLM CORP\\svc SYNTHBITS000",
    "bitsadmin /SetCredentials Job SERVER NTLM CORP\\svc REDACTED-SECRET-1",
  ],
  [
    "rasdial, entry and user kept",
    "rasdial ContosoVPN vpnuser SYNTHRAS0000",
    "rasdial ContosoVPN vpnuser REDACTED-SECRET-1",
  ],
];

for (const [label, input, expected] of POSITIONAL_CASES) {
  test(`positional credential: ${label}`, () => {
    const red = r();
    const out = red.redact(input);
    assert.equal(out.text, expected);
    assert.equal(red.redact(out.text).text, out.text);
  });
}

// The documented innocent variants. Every one of these is a real administrative command line that
// carries no credential, and each is the shape a slightly greedier anchor would eat.
const POSITIONAL_NEGATIVES = [
  "net user bob * /add",
  "net user bob /delete",
  "net user /domain",
  "net user",
  "net use Z: \\\\fs01\\backups /persistent:yes",
  "net use * /delete",
  "net use",
  "rasdial ContosoVPN /disconnect",
  "rasdial",
  "bitsadmin /list /allusers",
];

for (const text of POSITIONAL_NEGATIVES) {
  test(`positional credential negative: ${text}`, () => {
    assert.equal(r().redact(text).text, text);
  });
}
