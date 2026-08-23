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
