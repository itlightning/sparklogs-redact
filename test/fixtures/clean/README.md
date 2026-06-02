# Clean fixtures (synthetic)

Placeholder log lines with **no** PII-shaped tokens (no user-profile paths, emails, customer hostnames, etc.).
Used by `make ci` / CLI tests for `scan` exit 0.

Use the **`.fixture`** suffix for committed synthetic log text (not `*.log`, which `.gitignore` excludes so
ad-hoc local trials never land in git). Add more `*.fixture` files here as coverage grows; keep everything
generic per workspace `no-customer-data-in-source` placeholders (`example.com`, `host-a`, TEST-NET IPs, etc.).
