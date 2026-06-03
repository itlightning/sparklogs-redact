import * as Icon from "../icons.tsx";
import { useFlow } from "../flow.tsx";
import { FileRow, Note } from "./shared.tsx";

export function StepReview() {
  const { files } = useFlow();
  const counts = { text: 0, binary: 0, rejected: 0 };
  files.forEach((f) => {
    if (f.det) counts[f.det.kind]++;
  });
  return (
    <div>
      <div className="slup__detectSummary">
        <div className="slup__stat">
          <div className="slup__statNum slup__spark">{counts.text}</div>
          <div className="slup__statLabel">Text files → redacted</div>
        </div>
        <div className="slup__stat">
          <div className="slup__statNum" style={{ color: "var(--slup-accent)" }}>
            {counts.binary}
          </div>
          <div className="slup__statLabel">Images / docs → as-is</div>
        </div>
        <div className="slup__stat">
          <div className="slup__statNum" style={{ color: "var(--slup-text-muted)" }}>
            {counts.rejected}
          </div>
          <div className="slup__statLabel">Skipped (not allowed)</div>
        </div>
      </div>
      <Note icon={Icon.Info}>
        We classify each file by its bytes: a valid UTF byte-order mark or 2 KB of valid UTF-8 means{" "}
        <strong>text</strong> (gets redacted). Images and office documents on our allow-list upload
        as-is. Anything else is skipped. If something looks miscategorized, head back and remove it.
      </Note>
      <div style={{ marginTop: 18 }}>
        <div className="slup__list">
          {files.map((f) => (
            <FileRow key={f.id} file={f} removable />
          ))}
        </div>
      </div>
    </div>
  );
}
