import { test } from "node:test";
import assert from "node:assert/strict";
import { detectEncoding, decode } from "../src/encoding.ts";

function bytes(...b: number[]): Uint8Array {
  return new Uint8Array(b);
}

test("detectEncoding: UTF-8 BOM", () => {
  const info = detectEncoding(bytes(0xef, 0xbb, 0xbf, 0x41, 0x42));
  assert.equal(info.encoding, "utf-8");
  assert.equal(info.bom, true);
});

test("detectEncoding: UTF-16LE BOM", () => {
  const info = detectEncoding(bytes(0xff, 0xfe, 0x41, 0x00));
  assert.equal(info.encoding, "utf-16le");
  assert.equal(info.bom, true);
});

test("detectEncoding: UTF-16BE BOM", () => {
  const info = detectEncoding(bytes(0xfe, 0xff, 0x00, 0x41));
  assert.equal(info.encoding, "utf-16be");
  assert.equal(info.bom, true);
});

test("detectEncoding: plain ASCII -> utf-8, no BOM", () => {
  const info = detectEncoding(new TextEncoder().encode("hello world\n"));
  assert.equal(info.encoding, "utf-8");
  assert.equal(info.bom, false);
});

test("detectEncoding: BOM-less UTF-16LE via NUL-lane heuristic", () => {
  // "ABCD" as UTF-16LE without BOM: 0x41 0x00 0x42 0x00 ...
  const le: number[] = [];
  for (const ch of "ABCDEFGHIJ") {
    le.push(ch.charCodeAt(0), 0x00);
  }
  const info = detectEncoding(bytes(...le));
  assert.equal(info.encoding, "utf-16le");
  assert.equal(info.bom, false);
});

test("detectEncoding: BOM-less UTF-16BE via NUL-lane heuristic", () => {
  const be: number[] = [];
  for (const ch of "ABCDEFGHIJ") {
    be.push(0x00, ch.charCodeAt(0));
  }
  const info = detectEncoding(bytes(...be));
  assert.equal(info.encoding, "utf-16be");
  assert.equal(info.bom, false);
});

test("detectEncoding: empty buffer -> utf-8", () => {
  const info = detectEncoding(bytes());
  assert.equal(info.encoding, "utf-8");
  assert.equal(info.bom, false);
});

test("decode: strips UTF-8 BOM", () => {
  const out = decode(bytes(0xef, 0xbb, 0xbf, 0x68, 0x69));
  assert.equal(out, "hi");
});

test("decode: UTF-16LE BOM round-trips", () => {
  const out = decode(bytes(0xff, 0xfe, 0x68, 0x00, 0x69, 0x00));
  assert.equal(out, "hi");
});

test("decode: plain UTF-8 round-trips with multibyte", () => {
  const s = "café — déjà\n";
  const out = decode(new TextEncoder().encode(s));
  assert.equal(out, s);
});
