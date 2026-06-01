# Clean fixtures (synthetic)

Placeholder log lines with **no** PII-shaped tokens (no user-profile paths, emails, customer hostnames, etc.).
Used by `make ci` / CLI tests for `scan` exit 0.

Add more files here as you grow regression coverage; keep everything generic per workspace
`no-customer-data-in-source` placeholders (`example.com`, `host-a`, TEST-NET IPs, etc.).
