import { test, expect } from "vitest";
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
  // TS 5.7+ types `Uint8Array` as possibly SharedArrayBuffer-backed, which isn't a valid BlobPart;
  // our buffers are always ArrayBuffer-backed, so the cast is safe.
  return new File([data as BlobPart], name);
}

test("classifyFile: valid UTF-8 log is text and will redact", async () => {
  const det = await classifyFile(file("cbs.log", "2026-06-01 INFO starting up\nline two\n"), policy);
  expect(det.kind).toBe("text");
  expect(det.willRedact).toBe(true);
  expect(det.willUpload).toBe(true);
  expect(det.previewable).toBe(true);
});

test("classifyFile: NUL-laden bytes with an image extension are accepted as binary, not redacted", async () => {
  const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]);
  const det = await classifyFile(file("shot.png", bytes), policy);
  expect(det.kind).toBe("binary");
  expect(det.isImage).toBe(true);
  expect(det.willRedact).toBe(false);
  expect(det.willUpload).toBe(true);
  expect(det.previewable).toBe(true);
});

test("classifyFile: unknown binary is rejected and will not upload", async () => {
  const bytes = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x00, 0x10]);
  const det = await classifyFile(file("blob.bin", bytes), policy);
  expect(det.kind).toBe("rejected");
  expect(det.willUpload).toBe(false);
  expect(det.willRedact).toBe(false);
});

test("classifyFile: UTF-8 BOM marks text", async () => {
  const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode("hello")]);
  const det = await classifyFile(file("notes.txt", bytes), policy);
  expect(det.kind).toBe("text");
  expect(det.encoding).toBe("UTF-8 (BOM)");
});
