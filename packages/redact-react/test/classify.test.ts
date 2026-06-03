import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyFile, DEFAULT_DOC_EXTS, DEFAULT_IMAGE_EXTS } from "../src/classify.ts";
import type { ClassifyPolicy } from "../src/types.ts";

const policy: ClassifyPolicy = {
  maxTotalBytes: 100 * 1024 * 1024,
  maxFiles: 250,
  imageExtensions: new Set(DEFAULT_IMAGE_EXTS),
  docExtensions: new Set(DEFAULT_DOC_EXTS),
};

function file(name: string, bytes: Uint8Array | string): File {
  const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  return new File([data], name);
}

test("classifyFile: valid UTF-8 log is text and will redact", async () => {
  const det = await classifyFile(file("cbs.log", "2026-06-01 INFO starting up\nline two\n"), policy);
  assert.equal(det.kind, "text");
  assert.equal(det.willRedact, true);
  assert.equal(det.willUpload, true);
  assert.equal(det.previewable, true);
});

test("classifyFile: NUL-laden bytes with an image extension are accepted as binary, not redacted", async () => {
  const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]);
  const det = await classifyFile(file("shot.png", bytes), policy);
  assert.equal(det.kind, "binary");
  assert.equal(det.isImage, true);
  assert.equal(det.willRedact, false);
  assert.equal(det.willUpload, true);
  assert.equal(det.previewable, true);
});

test("classifyFile: unknown binary is rejected and will not upload", async () => {
  const bytes = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x00, 0x10]);
  const det = await classifyFile(file("blob.bin", bytes), policy);
  assert.equal(det.kind, "rejected");
  assert.equal(det.willUpload, false);
  assert.equal(det.willRedact, false);
});

test("classifyFile: UTF-8 BOM marks text", async () => {
  const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode("hello")]);
  const det = await classifyFile(file("notes.txt", bytes), policy);
  assert.equal(det.kind, "text");
  assert.equal(det.encoding, "UTF-8 (BOM)");
});
