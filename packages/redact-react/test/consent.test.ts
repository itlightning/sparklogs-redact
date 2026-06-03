import { test } from "node:test";
import assert from "node:assert/strict";
import { initConsents, toggleConsent, validateConsents } from "../src/consent.ts";
import type { ConsentItem } from "../src/types.ts";

const ITEMS: ConsentItem[] = [
  { id: "support", label: "Support", desc: "", required: true, group: "primary" },
  { id: "product", label: "Product", desc: "", group: "optional" },
  { id: "community", label: "Community", desc: "", group: "optional", implies: ["product"] },
];

test("initConsents: everything starts unchecked", () => {
  assert.deepEqual(initConsents(ITEMS), { support: false, product: false, community: false });
});

test("toggleConsent: checking a child also checks what it implies", () => {
  let c = initConsents(ITEMS);
  c = toggleConsent(c, ITEMS, "community");
  assert.equal(c.community, true);
  assert.equal(c.product, true, "community implies product");
});

test("toggleConsent: unchecking a parent also unchecks anything that implies it", () => {
  let c = { support: true, product: true, community: true };
  c = toggleConsent(c, ITEMS, "product");
  assert.equal(c.product, false);
  assert.equal(c.community, false, "community can't stay checked without product");
  assert.equal(c.support, true, "unrelated consent untouched");
});

test("toggleConsent: checking the parent alone does not check the child", () => {
  let c = initConsents(ITEMS);
  c = toggleConsent(c, ITEMS, "product");
  assert.equal(c.product, true);
  assert.equal(c.community, false);
});

test("validateConsents: flags only unchecked required items", () => {
  assert.deepEqual(validateConsents({ support: false, product: false, community: false }, ITEMS), {
    support: "Required to proceed",
  });
  assert.deepEqual(validateConsents({ support: true, product: false, community: false }, ITEMS), {});
});
