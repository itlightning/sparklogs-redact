import { lazy, Suspense } from "react";
import * as Icon from "../icons.tsx";
import { fmtBytes } from "../util.ts";
import { useFlow, type WizardFile } from "../flow.tsx";
import type { PreviewRenderArgs } from "../types.ts";
import { Note } from "./shared.tsx";

// Lazy so the CodeMirror dependency only loads when a text preview is actually rendered. The factory
// is shared with `prefetchCodeMirrorPreview` so a warm-up (kicked off at mount) and the actual render
// resolve the same module instead of fetching the chunk twice.
const importCodeMirrorPreview = () => import("./CodeMirrorPreview.tsx");
const CodeMirrorPreview = lazy(importCodeMirrorPreview);

/**
 * Start fetching the lazy CodeMirror chunk ahead of the preview step. Safe to call repeatedly (the
 * dynamic import is cached) and a no-op-ish cost if the user never reaches a text preview. Skip it
 * when a host `renderPreview` is supplied, since CodeMirror is then never used.
 */
export function prefetchCodeMirrorPreview(): void {
  void importCodeMirrorPreview();
}

/** Renders a text document: the host's `renderPreview` if provided, else the default CM6 viewer. */
function TextPreview(args: PreviewRenderArgs) {
  const { renderPreview } = useFlow();
  if (renderPreview) return <>{renderPreview(args)}</>;
  return (
    <Suspense fallback={<div className="slup__code">Loading preview…</div>}>
      <CodeMirrorPreview {...args} />
    </Suspense>
  );
}

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

function selectedFile(flow: ReturnType<typeof useFlow>): WizardFile | undefined {
  return flow.uploadable.find((x) => x.id === flow.sel) || flow.uploadable[0];
}

/** Build the preview args for a file's redacted text (highlights + reveal data). */
function redactedArgs(f: WizardFile, flow: ReturnType<typeof useFlow>): PreviewRenderArgs {
  return {
    text: f.redactedText ?? "",
    redactions: f.redactions,
    originalText: f.originalText,
    reveal: flow.reveal && flow.allowRevealOriginal,
    wrap: flow.wrap,
    categoryFor: flow.categoryFor,
    usage: flow.summary?.usage,
  };
}

function Viewer() {
  const flow = useFlow();
  const { reveal, wrap, allowRevealOriginal, urlFor, policy } = flow;
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
        {isText ? (
          <div className="slup__viewerTools">
            <button
              className={"slup__toggle" + (wrap ? " slup__toggle--on" : "")}
              onClick={() => flow.setWrap((v) => !v)}
              aria-pressed={wrap}
              title="Toggle soft line wrapping in the preview."
            >
              <Icon.WrapText />
              {wrap ? "Wrapping" : "No wrap"}
            </button>
            {allowRevealOriginal ? (
              <button
                className={"slup__toggle" + (reveal ? " slup__toggle--on" : "")}
                onClick={() => flow.setReveal((v) => !v)}
                aria-pressed={reveal}
                title="Local-only. Shows the original values that were replaced."
              >
                {reveal ? <Icon.Eye /> : <Icon.EyeOff />}
                {reveal ? "Showing original" : "Reveal original"}
              </button>
            ) : null}
          </div>
        ) : null}
      </div>
      {isText ? (
        <TextPreview {...redactedArgs(f, flow)} />
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
          <button
            className={"slup__toggle" + (flow.wrap ? " slup__toggle--on" : "")}
            onClick={() => flow.setWrap((v) => !v)}
            aria-pressed={flow.wrap}
            title="Toggle soft line wrapping in the preview."
          >
            <Icon.WrapText />
            {flow.wrap ? "Wrapping" : "No wrap"}
          </button>
          <span className="slup__splitHint">Original → Redacted</span>
        </div>
      </div>
      <div className="slup__split">
        <div className="slup__splitOrig">
          <TextPreview text={f.originalText ?? ""} wrap={flow.wrap} />
        </div>
        <TextPreview {...redactedArgs(f, flow)} />
      </div>
    </div>
  );
}

export function StepRedact() {
  const flow = useFlow();
  const { redacting, redactProgress, summary, textFiles, uploadable, sel, previewStyle, categoryFor, policy, cancelRedaction } =
    flow;

  if (redacting) {
    const p = redactProgress;
    return (
      <div className="slup__empty" role="status" aria-live="polite">
        <div className="slup__dropIcon" style={{ margin: "0 auto 16px" }} aria-hidden="true">
          <Icon.Cpu className="slup__spin" />
        </div>
        <div style={{ fontWeight: 700, fontSize: "1.1rem" }}>
          {"Anonymizing " + textFiles.length + " text file" + (textFiles.length > 1 ? "s" : "") + "…"}
        </div>
        <div style={{ color: "var(--slup-text-muted)", marginTop: 6 }}>
          {p && p.total > 1
            ? "Processed " + p.done + " of " + p.total + " files."
            : "Runs on your device; the UI stays responsive."}
        </div>
        <button
          className="slup__btn slup__btn--quiet"
          style={{ marginTop: 16 }}
          onClick={cancelRedaction}
        >
          <Icon.X />
          Cancel
        </button>
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
