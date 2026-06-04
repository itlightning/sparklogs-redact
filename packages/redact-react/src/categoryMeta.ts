import type { CategoryDisplay } from "./types.ts";

/**
 * Default display metadata for every category @sparklogs/redact-core can emit. Colors reference
 * `--slup-cat-*` custom properties (themeable). Hosts can override any entry via the
 * `categoryMeta` prop.
 */
export const DEFAULT_CATEGORY_META: Record<string, CategoryDisplay> = {
  username: {
    label: "Usernames",
    color: "var(--slup-cat-username)",
    desc: "Account names in home-directory paths",
  },
  email: { label: "Email addresses", color: "var(--slup-cat-email)", desc: "user@domain.tld" },
  ipv4: { label: "IPv4 addresses", color: "var(--slup-cat-ip)", desc: "Dotted-quad addresses" },
  ipv6: { label: "IPv6 addresses", color: "var(--slup-cat-ip)", desc: "IPv6 literals" },
  mac: { label: "MAC addresses", color: "var(--slup-cat-mac)", desc: "Hardware addresses" },
  creditcard: {
    label: "Payment cards",
    color: "var(--slup-cat-card)",
    desc: "Luhn-valid card numbers",
  },
  ssn: {
    label: "Social security numbers",
    color: "var(--slup-cat-ssn)",
    desc: "US SSN-formatted numbers",
  },
  phone: { label: "Phone numbers", color: "var(--slup-cat-phone)", desc: "E.164 / NANP numbers" },
  host: { label: "Hostnames", color: "var(--slup-cat-host)", desc: "UNC / fully-qualified names" },
  sid: { label: "Windows SIDs", color: "var(--slup-cat-sid)", desc: "Security identifiers" },
  token: {
    label: "Tokens & keys",
    color: "var(--slup-cat-secret)",
    desc: "JWTs, cloud keys, bearer tokens",
  },
  secret: {
    label: "Secrets",
    color: "var(--slup-cat-secret)",
    desc: "Passwords, private keys, credentials",
  },
};

/**
 * Categories that are ALWAYS redacted and can never be toggled off in the wizard — high-harm PII
 * (payment cards, SSNs, emails) and credentials (secrets, tokens). `redactionRules` cannot unlock these.
 */
export const LOCKED_CATEGORIES: ReadonlySet<string> = new Set([
  "creditcard",
  "ssn",
  "email",
  "secret",
  "token",
]);

/**
 * Default `redactionRules`: which discretionary categories are user-toggleable, and each one's default
 * enabled state. A category absent here (and not locked) is always-on and NOT customizable. Hosts
 * override via the `redactionRules` prop — e.g. SparkLogs ships host/username/sid off.
 */
export const DEFAULT_REDACTION_RULES: Record<string, boolean> = {
  username: true,
  sid: true,
  ipv4: true,
  ipv6: true,
  mac: true,
  phone: true,
  host: false,
};

/** A neutral fallback for any category not in the map. */
export const FALLBACK_CATEGORY: CategoryDisplay = {
  label: "Redacted",
  color: "var(--slup-accent)",
  desc: "Detected sensitive value",
};

/** Merge host overrides onto the defaults, filling gaps from the fallback. */
export function resolveCategoryMeta(
  overrides?: Record<string, Partial<CategoryDisplay>>,
): (category: string) => CategoryDisplay {
  return (category: string) => {
    const base = DEFAULT_CATEGORY_META[category] ?? {
      ...FALLBACK_CATEGORY,
      label: category,
    };
    const o = overrides?.[category];
    return o ? { ...base, ...o } : base;
  };
}
