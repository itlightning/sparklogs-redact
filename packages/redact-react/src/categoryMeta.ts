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
