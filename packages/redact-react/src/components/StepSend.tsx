import * as Icon from "../icons.tsx";
import { fmtBytes } from "../util.ts";
import { useFlow } from "../flow.tsx";
import { Note } from "./shared.tsx";

function Confirmation() {
  const { uploadable, totalSize, summary, form, consentItems, refId, resetAll } = useFlow();
  const redTotal = summary ? Object.values(summary.totals).reduce((a, b) => a + b, 0) : 0;
  const catCount = summary ? Object.keys(summary.totals).length : 0;
  const perms = consentItems.filter((c) => form.consents[c.id]).map((c) => c.label);
  return (
    <div className="slup__confirm">
      <div className="slup__confirmIcon">
        <Icon.Check />
      </div>
      <h2 className="slup__confirmTitle">Upload complete</h2>
      <p className="slup__confirmSub">
        {"Thanks, " + (form.name.split(" ")[0] || "there") + ". Your redacted files were received and the team will follow up by email."}
      </p>
      <div className="slup__ref">
        <div>
          <div className="slup__refLabel">Reference</div>
          <div className="slup__refVal">{refId}</div>
        </div>
        <button
          className="slup__btn slup__btn--quiet"
          onClick={() => navigator.clipboard && navigator.clipboard.writeText(refId)}
          title="Copy"
        >
          <Icon.Copy />
        </button>
      </div>
      <div className="slup__receipt">
        <dl>
          <dt>Files uploaded</dt>
          <dd>{uploadable.length + " · " + fmtBytes(totalSize)}</dd>
          <dt>Values redacted</dt>
          <dd>{redTotal + " across " + catCount + " categories"}</dd>
          <dt>Contact</dt>
          <dd>{form.email}</dd>
          <dt>Permissions</dt>
          <dd>{perms.join(", ") || "None"}</dd>
        </dl>
      </div>
      <button className="slup__btn slup__btn--ghost" style={{ marginTop: 22 }} onClick={resetAll}>
        <Icon.Plus />
        Upload more
      </button>
    </div>
  );
}

export function StepSend() {
  const flow = useFlow();
  const { upState, upError, upProgress, uploadable, totalSize, startUpload, cancelUpload, goto } = flow;

  if (upState === "done") return <Confirmation />;

  if (upState === "error") {
    return (
      <div className="slup__upWrap">
        <Note variant="bad" icon={Icon.Alert}>
          {upError}
        </Note>
        <div style={{ display: "flex", gap: 10, justifyContent: "center", marginTop: 22 }}>
          <button className="slup__btn slup__btn--ghost" onClick={() => goto(3)}>
            <Icon.ChevronLeft />
            Back to details
          </button>
          <button className="slup__btn slup__btn--primary" onClick={() => void startUpload()}>
            <Icon.UploadCloud />
            Try again
          </button>
        </div>
      </div>
    );
  }

  // running
  const pct =
    upProgress && upProgress.total > 0
      ? Math.min(100, Math.round((upProgress.loaded / upProgress.total) * 100))
      : null;
  return (
    <div className="slup__upWrap">
      <div className="slup__upBig">
        <div className="slup__upPct">
          {pct != null ? pct + "%" : <Icon.Loader className="slup__spin" />}
        </div>
        <div className="slup__upState">
          {"Uploading " + uploadable.length + " redacted file" + (uploadable.length > 1 ? "s" : "") + " over TLS…"}
        </div>
      </div>
      <div className="slup__meterTrack" style={{ height: 10, marginBottom: 18 }}>
        <div className="slup__meterFill" style={{ width: (pct ?? 4) + "%" }} />
      </div>
      <div className="slup__upList">
        {uploadable.map((f) => (
          <div key={f.id} className="slup__upRow">
            <span className="slup__upDot slup__upDot--active">
              <Icon.Loader className="slup__spin" />
            </span>
            <span className="slup__upRowName" title={f.path}>
              {f.name}
            </span>
            <span style={{ color: "var(--slup-text-muted)", fontVariantNumeric: "tabular-nums" }}>
              {fmtBytes(f.size)}
            </span>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 16 }}>
        <span className="slup__footNote">{"Sending " + fmtBytes(totalSize) + " — stays on this page until done."}</span>
        <button className="slup__btn slup__btn--quiet" onClick={cancelUpload}>
          <Icon.X />
          Cancel
        </button>
      </div>
    </div>
  );
}
