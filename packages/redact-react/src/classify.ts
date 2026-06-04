// File classification: decide text / allow-listed binary / rejected by sniffing the leading bytes.
// Encoding detection comes from @sparklogs/redact-core; the binary-vs-text DECISION (control-byte
// ratio + strict UTF-8) lives here because the core scanner only deals in already-decoded text.
import { detectEncoding } from "@sparklogs/redact-core";
import type { ClassifyPolicy, Detection } from "./types.ts";

const SNIFF_BYTES = 2048;

export function extOf(name: string): string {
  const m = /\.([A-Za-z0-9]+)$/.exec(name || "");
  return m ? m[1].toLowerCase() : "";
}

function encodingLabel(bytes: Uint8Array): string {
  const info = detectEncoding(bytes);
  if (info.encoding === "utf-16le") return "UTF-16 LE";
  if (info.encoding === "utf-16be") return "UTF-16 BE";
  return info.bom ? "UTF-8 (BOM)" : "UTF-8";
}

/** Ratio of disallowed control bytes (excludes \t \n \r). A NUL forces a binary verdict. */
function controlRatio(bytes: Uint8Array): number {
  if (!bytes.length) return 1;
  let ctrl = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0) return 1;
    if (b < 0x09 || (b > 0x0d && b < 0x20)) ctrl++;
  }
  return ctrl / bytes.length;
}

/** Strict UTF-8 decode of the sample; retry trimming up to 3 bytes that may split a codepoint. */
function isValidUtf8(bytes: Uint8Array): boolean {
  for (let trim = 0; trim <= 3; trim++) {
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, bytes.length - trim));
      return true;
    } catch {
      /* keep trimming */
    }
  }
  return false;
}

export const DEFAULT_IMAGE_EXTS = [
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "bmp",
  "svg",
  "heic",
  "heif",
  "tiff",
  "tif",
  "ico",
  "avif",
];
export const DEFAULT_DOC_EXTS = [
  "pdf",
  "doc",
  "docx",
  "xls",
  "xlsx",
  "ppt",
  "pptx",
  "odt",
  "ods",
  "odp",
  "rtf",
];

/** Classify a File by sniffing its first {@link SNIFF_BYTES} bytes. */
export async function classifyFile(file: File, policy: ClassifyPolicy): Promise<Detection> {
  const ext = extOf(file.name);
  const buf = await file.slice(0, SNIFF_BYTES).arrayBuffer();
  const bytes = new Uint8Array(buf);

  const info = detectEncoding(bytes);
  if (info.bom) return make("text", encodingLabel(bytes), ext, "Valid byte-order marker");

  if (controlRatio(bytes) < 0.12 && isValidUtf8(bytes)) {
    return make("text", "UTF-8", ext, "First 2 KB is valid UTF-8");
  }
  if (policy.imageExtensions.has(ext)) {
    return make("binary", "binary", ext, "Image (allow-listed), uploaded as-is, not redacted", {
      previewable: true,
      isImage: true,
    });
  }
  if (policy.docExtensions.has(ext)) {
    return make("binary", "binary", ext, "Document (allow-listed), uploaded as-is, not redacted");
  }
  return make("rejected", "binary", ext, "Binary file, not on the allow-list, will be skipped");

  function make(
    kind: Detection["kind"],
    encoding: string,
    ext2: string,
    reason: string,
    extra?: { previewable?: boolean; isImage?: boolean },
  ): Detection {
    return {
      kind,
      encoding,
      ext: ext2,
      reason,
      willUpload: kind !== "rejected",
      willRedact: kind === "text",
      previewable: kind === "text" || !!extra?.previewable,
      isImage: !!extra?.isImage,
    };
  }
}
