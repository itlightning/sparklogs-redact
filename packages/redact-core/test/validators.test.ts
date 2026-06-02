import { test } from "node:test";
import assert from "node:assert/strict";
import { luhn, VALIDATORS } from "../src/validators.ts";

test("luhn: accepts a valid mod-10 sequence, rejects a one-off and the empty string", () => {
  assert.equal(luhn("4111111111111111"), true);
  assert.equal(luhn("4111111111111112"), false);
  assert.equal(luhn(""), false); // no digits seen
  assert.equal(luhn("abc"), false); // no digits seen
});

test("creditcard validator: brand prefix + length + Luhn together", () => {
  const cc = VALIDATORS.creditcard;
  assert.equal(cc("4111 1111 1111 1111"), true); // Visa test number (16, MII 4)
  assert.equal(cc("378282246310005"), true); // Amex test number (15, MII 3)
  assert.equal(cc("4111 1111 1111 1112"), false); // right shape, fails Luhn
  assert.equal(cc("1234567890123456"), false); // MII 1 -> not a card brand
  assert.equal(cc("4111 1111 1111"), false); // 12 digits -> wrong length
  assert.equal(cc("37828224631000"), false); // 14-digit Amex-prefix -> length rule
});

test("ssn validator: rejects never-assigned area/group/serial", () => {
  const ssn = VALIDATORS.ssn;
  assert.equal(ssn("123-45-6789"), true);
  assert.equal(ssn("000-12-3456"), false); // area 000
  assert.equal(ssn("666-12-3456"), false); // area 666
  assert.equal(ssn("900-12-3456"), false); // area >= 900
  assert.equal(ssn("123-00-6789"), false); // group 00
  assert.equal(ssn("123-45-0000"), false); // serial 0000
});
