// Off-main-thread redaction worker. Receives File handles, decodes + redacts them with
// @sparklogs/redact-core (pure string/regex — safe in a worker), reports file-level progress, and
// posts the result back. The host falls back to a synchronous in-thread pass if this worker can't be
// constructed (see worker-runner.ts), so it is purely an optimization.
import { decode } from "@sparklogs/redact-core";
import { runRedaction } from "./redaction.ts";
import type { ProfileName } from "./types.ts";

interface RedactMessage {
  type: "redact";
  files: { id: string; file: File }[];
  profiles: ProfileName[];
  needsOriginal: boolean;
}

const post = (m: unknown) => (self as unknown as { postMessage(m: unknown): void }).postMessage(m);

self.onmessage = async (e: MessageEvent<RedactMessage>) => {
  const msg = e.data;
  if (!msg || msg.type !== "redact") return;
  try {
    const total = msg.files.length;
    const reads = await Promise.all(
      msg.files.map(async (f) => {
        try {
          return { id: f.id, text: decode(new Uint8Array(await f.file.arrayBuffer())) };
        } catch {
          return { id: f.id, text: "" };
        }
      }),
    );
    const originals: Record<string, string> = {};
    if (msg.needsOriginal) for (const r of reads) originals[r.id] = r.text;
    const summary = runRedaction(reads, msg.profiles, (done) =>
      post({ type: "progress", done, total }),
    );
    post({ type: "result", summary, originals });
  } catch (err) {
    post({ type: "error", message: (err as Error)?.message ?? "redaction failed" });
  }
};
