import { Fragment } from "react";
import * as Icon from "../icons.tsx";
import { fmtBytes } from "../util.ts";
import { buildSegments } from "../redaction.ts";
import { useFlow, type WizardFile } from "../flow.tsx";
import { Note } from "./shared.tsx";

function Legend() {
  const { summary, categoryFor } = useFlow();
  if (!summary) return null;
  const keys = Object.keys(summary.totals);
  if (!keys.length)
    return (
      <Note icon={Icon.ShieldCheck}>
        No PII patterns matched in these files. Nothing needed redacting.
      </Note>
    );
  return (
    <div className="slup__legend">
      {keys.map((k) => {
        const meta = categoryFor(k);
        return (
          <span key={k} className="slup__legChip">
            <span className="slup__legDot" style={{ background: meta.color }} />
            {meta.label}
            <span className="slup__legCount">{summary.totals[k]}</span>
          </span>
        );
      })}
    </div>
  );
}

function RedactedText({ file }: { file: WizardFile }) {
  const { summary, reveal, allowRevealOriginal, categoryFor, showTip, hideTip } = useFlow();
  const text = file.redactedText ?? "";
  if (!summary || !file.redactions) return <>{text}</>;
  const segments = buildSegments(text, file.redactions, file.originalText);
  const revealing = reveal && allowRevealOriginal;
  return (
    <>
      {segments.map((seg, i) => {
        if (!seg.pill) return <Fragment key={i}>{seg.text}</Fragment>;
        const meta = categoryFor(seg.pill.category);
        const u = summary.usage.get(seg.pill.replacement);
        const metaText = u
          ? "Maps to " +
            seg.pill.replacement +
            " everywhere. Appears " +
            u.count +
            "× across " +
            u.files.size +
            " file" +
            (u.files.size > 1 ? "s" : "") +
            "."
          : seg.pill.replacement;
        const shown = revealing && seg.pill.original != null ? seg.pill.original : seg.text;
        return (
          <span
            key={i}
            className="slup__pill"
            data-revealed={revealing ? "1" : "0"}
            style={{ ["--pc" as any]: meta.color }}
            tabIndex={0}
            onMouseEnter={(e) => showTip(e, meta.label, meta.color, metaText)}
            onMouseLeave={hideTip}
            onFocus={(e) => showTip(e, meta.label, meta.color, metaText)}
            onBlur={hideTip}
          >
            {shown}
          </span>
        );
      })}
    </>
  );
}

function selectedFile(flow: ReturnType<typeof useFlow>): WizardFile | undefined {
  return flow.uploadable.find((x) => x.id === flow.sel) || flow.uploadable[0];
}

function Viewer() {
  const flow = useFlow();
  const { reveal, allowRevealOriginal, urlFor, policy } = flow;
  const f = selectedFile(flow);
  if (!f)
    return (
      <div className="slup__viewer">
        <div className="slup__docFallback">Select a file to preview</div>
      </div>
    );
  const isText = f.det!.kind === "text";
  const isImg = f.det!.kind === "binary" && policy.imageExtensions.has(f.det!.ext);
  return (
    <div className="slup__viewer">
      <div className="slup__viewerBar">
        <span className="slup__viewerName" title={f.path}>
          {f.path}
        </span>
        {isText && allowRevealOriginal ? (
          <div className="slup__viewerTools">
            <button
              className={"slup__toggle" + (reveal ? " slup__toggle--on" : "")}
              onClick={() => flow.setReveal((v) => !v)}
              title="Local-only. Shows the original values that were replaced."
            >
              {reveal ? <Icon.Eye /> : <Icon.EyeOff />}
              {reveal ? "Showing original" : "Reveal original"}
            </button>
          </div>
        ) : null}
      </div>
      {isText ? (
        <pre className="slup__code">
          <RedactedText file={f} />
        </pre>
      ) : isImg ? (
        <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
          <div className="slup__imgWrap">
            <img src={urlFor(f)} alt={f.name} />
          </div>
          <div className="slup__imgNote">
            Images upload as-is and are not auto-redacted. Check screenshots for visible PII before
            sending.
          </div>
        </div>
      ) : (
        <div className="slup__docFallback">
          <Icon.File />
          <div>{"." + f.det!.ext + " document"}</div>
          <div style={{ fontSize: ".8rem", marginTop: 6 }}>{"Uploaded as-is · " + fmtBytes(f.size)}</div>
        </div>
      )}
    </div>
  );
}

function SplitViewer() {
  const flow = useFlow();
  const f = selectedFile(flow);
  if (!f || f.det!.kind !== "text") return <Viewer />;
  return (
    <div className="slup__viewer">
      <div className="slup__viewerBar">
        <span className="slup__viewerName" title={f.path}>
          {f.path}
        </span>
        <div className="slup__viewerTools">
          <span className="slup__splitHint">Original → Redacted</span>
        </div>
      </div>
      <div className="slup__split">
        <pre className="slup__code slup__splitOrig">{f.originalText ?? "(loading…)"}</pre>
        <pre className="slup__code">
          <RedactedText file={f} />
        </pre>
      </div>
    </div>
  );
}

export function StepRedact() {
  const flow = useFlow();
  const { redacting, summary, textFiles, uploadable, sel, previewStyle, categoryFor, policy } = flow;

  if (redacting) {
    return (
      <div className="slup__empty">
        <div className="slup__dropIcon" style={{ margin: "0 auto 16px" }}>
          <Icon.Cpu className="slup__spin" />
        </div>
        <div style={{ fontWeight: 700, fontSize: "1.1rem" }}>
          {"Anonymizing " + textFiles.length + " text file" + (textFiles.length > 1 ? "s" : "") + "…"}
        </div>
        <div style={{ color: "var(--slup-text-muted)", marginTop: 6 }}>
          Building one shared map so matching IDs stay correlated across files.
        </div>
      </div>
    );
  }

  const totalRed = summary ? Object.values(summary.totals).reduce((a, b) => a + b, 0) : 0;
  const catCount = summary ? Object.keys(summary.totals).length : 0;

  return (
    <div>
      <Note icon={Icon.ShieldCheck}>
        {totalRed > 0 ? (
          <>
            Replaced <strong>{totalRed + " values"}</strong> across{" "}
            <strong>{catCount + " categories"}</strong>. Hover any{" "}
            <span className="slup__spark">highlight</span> to see how often it appears and that it
            maps consistently everywhere.
          </>
        ) : (
          "Review what we’re about to upload below."
        )}
      </Note>
      <Legend />
      <div className="slup__preview" style={{ marginTop: 16 }}>
        <div className="slup__previewList">
          {uploadable.map((f) => {
            const isImg = f.det!.kind === "binary" && policy.imageExtensions.has(f.det!.ext);
            const Comp = f.det!.kind === "text" ? Icon.FileText : isImg ? Icon.Image : Icon.File;
            return (
              <button
                key={f.id}
                className={"slup__pvItem" + (sel === f.id ? " slup__pvItem--active" : "")}
                onClick={() => flow.setSel(f.id)}
              >
                <Comp />
                <span className="slup__pvName" title={f.path}>
                  {f.name}
                </span>
              </button>
            );
          })}
        </div>
        {previewStyle === "split" ? <SplitViewer /> : <Viewer />}
      </div>
    </div>
  );
}
