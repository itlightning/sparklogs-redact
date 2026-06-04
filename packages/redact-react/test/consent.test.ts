import { test, expect } from "vitest";
import { initConsents, toggleConsent, validateConsents } from "../src/consent.ts";
import type { ConsentItem } from "../src/types.ts";

const ITEMS: ConsentItem[] = [
  { id: "support", label: "Support", desc: "", required: true, group: "primary" },
  { id: "product", label: "Product", desc: "", group: "optional" },
  { id: "community", label: "Community", desc: "", group: "optional", implies: ["product"] },
];

test("initConsents: everything starts unchecked", () => {
  expect(initConsents(ITEMS)).toEqual({ support: false, product: false, community: false });
});

test("toggleConsent: checking a child also checks what it implies", () => {
  let c = initConsents(ITEMS);
  c = toggleConsent(c, ITEMS, "community");
  expect(c.community).toBe(true);
  expect(c.product, "community implies product").toBe(true);
});

test("toggleConsent: unchecking a parent also unchecks anything that implies it", () => {
  let c: Record<string, boolean> = { support: true, product: true, community: true };
  c = toggleConsent(c, ITEMS, "product");
  expect(c.product).toBe(false);
  expect(c.community, "community can't stay checked without product").toBe(false);
  expect(c.support, "unrelated consent untouched").toBe(true);
});

test("toggleConsent: checking the parent alone does not check the child", () => {
  let c = initConsents(ITEMS);
  c = toggleConsent(c, ITEMS, "product");
  expect(c.product).toBe(true);
  expect(c.community).toBe(false);
});

test("validateConsents: flags only unchecked required items", () => {
  expect(validateConsents({ support: false, product: false, community: false }, ITEMS)).toEqual({
    support: "Required to proceed",
  });
  expect(validateConsents({ support: true, product: false, community: false }, ITEMS)).toEqual({});
});
