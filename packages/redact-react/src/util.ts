import { decode } from "@sparklogs/redact-core";

export function fmtBytes(n: number): string {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB"];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < 2);
  return (n < 10 ? n.toFixed(1) : Math.round(n)) + " " + u[i];
}

export const uid = (): string => Math.random().toString(36).slice(2, 9);

/** A human-friendly upload reference id, e.g. "SLU-260601-A3K2". */
export function genRef(): string {
  return (
    "SLU-" +
    new Date().toISOString().slice(2, 10).replace(/-/g, "") +
    "-" +
    uid().slice(0, 4).toUpperCase()
  );
}

/** Decode a file's bytes to text using the detected encoding (handles UTF-16 / BOM). */
export async function readFileText(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  return decode(new Uint8Array(buf));
}

export interface DroppedEntry {
  file: File;
  path: string;
}

// Directory-aware drag/drop: walk the webkit entry tree so dropping a folder ingests its files.
function walkEntry(entry: any, out: DroppedEntry[], prefix: string): Promise<void> {
  return new Promise((res) => {
    if (entry.isFile) {
      entry.file(
        (f: File) => {
          out.push({ file: f, path: prefix + entry.name });
          res();
        },
        () => res(),
      );
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const all: any[] = [];
      const batch = () =>
        reader.readEntries(
          (ents: any[]) => {
            if (!ents.length) {
              Promise.all(all.map((e) => walkEntry(e, out, prefix + entry.name + "/"))).then(() =>
                res(),
              );
            } else {
              all.push(...ents);
              batch();
            }
          },
          () => res(),
        );
      batch();
    } else res();
  });
}

export function fromDataTransfer(dt: DataTransfer): Promise<DroppedEntry[]> {
  const out: DroppedEntry[] = [];
  const ps: Promise<void>[] = [];
  const items = dt.items ? Array.from(dt.items) : [];
  if (items.length && (items[0] as any).webkitGetAsEntry) {
    for (const it of items) {
      const e = (it as any).webkitGetAsEntry && (it as any).webkitGetAsEntry();
      if (e) ps.push(walkEntry(e, out, ""));
      else {
        const f = it.getAsFile && it.getAsFile();
        if (f) out.push({ file: f, path: f.name });
      }
    }
    return Promise.all(ps).then(() => out);
  }
  return Promise.resolve(Array.from(dt.files || []).map((f) => ({ file: f, path: f.name })));
}
