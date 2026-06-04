// Runs the redaction pass off the main thread via a Web Worker when possible, with a synchronous
// in-thread fallback so it always works (SSR, unsupported environments, or a consumer bundler that
// didn't emit the worker). The worker is an optimization, never a requirement.
import type { ProfileName } from "./types.ts";
import { runRedaction, type RedactionSummary } from "./redaction.ts";
import { readFileText } from "./util.ts";

/** Host escape hatch: construct the worker yourself if your bundler needs specific syntax. */
export type CreateWorker = () => Worker;

export interface RedactRunResult {
  summary: RedactionSummary;
  /** Original decoded text per file id (empty unless `needsOriginal`). */
  originals: Record<string, string>;
}

interface RunOptions {
  needsOriginal: boolean;
  /** Only run detectors in these categories (locked + user-enabled). */
  enabledCategories: string[];
  onProgress?: (done: number, total: number) => void;
  signal?: AbortSignal;
  createWorker?: CreateWorker;
}

function defaultCreateWorker(): Worker {
  // Bundler-handled worker reference (Vite / webpack 5 / rspack emit the chunk and rewrite the URL).
  return new Worker(new URL("./redact.worker.js", import.meta.url), { type: "module" });
}

export async function runRedactionOffThread(
  files: { id: string; file: File }[],
  profiles: ProfileName[],
  opts: RunOptions,
): Promise<RedactRunResult> {
  let worker: Worker | null = null;
  if (typeof Worker !== "undefined") {
    try {
      worker = (opts.createWorker ?? defaultCreateWorker)();
    } catch {
      worker = null;
    }
  }
  if (!worker) return runInThread(files, profiles, opts);

  return await new Promise<RedactRunResult>((resolve, reject) => {
    const w = worker as Worker;
    let settled = false;
    const cleanup = () => {
      opts.signal?.removeEventListener("abort", onAbort);
      w.terminate();
    };
    const onAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new DOMException("Aborted", "AbortError"));
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    w.onmessage = (e: MessageEvent) => {
      const m = e.data;
      if (m?.type === "progress") {
        opts.onProgress?.(m.done, m.total);
        return;
      }
      if (settled) return;
      settled = true;
      cleanup();
      if (m?.type === "result") resolve({ summary: m.summary, originals: m.originals ?? {} });
      else reject(new Error(m?.message ?? "redaction failed"));
    };
    w.onerror = () => {
      // The worker script failed to load/run — fall back to an in-thread pass so redaction still works.
      if (settled) return;
      settled = true;
      cleanup();
      runInThread(files, profiles, opts).then(resolve, reject);
    };
    w.postMessage({
      type: "redact",
      files,
      profiles,
      enabledCategories: opts.enabledCategories,
      needsOriginal: opts.needsOriginal,
    });
  });
}

async function runInThread(
  files: { id: string; file: File }[],
  profiles: ProfileName[],
  opts: RunOptions,
): Promise<RedactRunResult> {
  const reads = await Promise.all(
    files.map(async (f) => {
      try {
        return { id: f.id, text: await readFileText(f.file) };
      } catch {
        return { id: f.id, text: "" };
      }
    }),
  );
  if (opts.signal?.aborted) throw new DOMException("Aborted", "AbortError");
  const originals: Record<string, string> = {};
  if (opts.needsOriginal) for (const r of reads) originals[r.id] = r.text;
  const summary = runRedaction(reads, profiles, opts.enabledCategories, opts.onProgress);
  return { summary, originals };
}
