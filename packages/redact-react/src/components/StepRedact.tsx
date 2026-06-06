import { lazy, Suspense, useEffect, useState } from "react";
import * as Icon from "../icons.tsx";
import { fmtBytes } from "../util.ts";
import { useFlow, type WizardFile } from "../flow.tsx";
import type { PreviewApi, PreviewRenderArgs } from "../types.ts";
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

/**
 * Toolbar controls that drive the default CodeMirror preview: jump to prev/next redaction (with a
 * position counter) and open the find panel. Rendered only for the built-in viewer — a host
 * `renderPreview` exposes no {@link PreviewApi}, so these controls are hidden there.
 */
function PreviewToolControls({
  api,
  total,
  bindFindKey,
}: {
  api: PreviewApi | null;
  total: number;
  bindFindKey: boolean;
}) {
  const [pos, setPos] = useState(0);

  // While mounted (i.e. on the preview step), bind Ctrl/Cmd+F to the find panel so it beats the
  // browser's native find, which can't see the virtualized text.
  useEffect(() => {
    if (!bindFindKey) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.altKey && (e.key === "f" || e.key === "F")) {
        if (e.defaultPrevented) return; // the editor's own keymap already handled it
        e.preventDefault();
        api?.openSearch();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [api, bindFindKey]);

  const jump = (dir: 1 | -1) => {
    const p = api?.gotoRedaction(dir);
    if (p) setPos(p);
  };
  const canJump = !!api && total > 0;

  return (
    <>
      <span className="slup__toolSep" aria-hidden="true" />
      {pos > 0 ? (
        <span className="slup__posCounter" aria-label={`${pos} of ${total} redactions`}>
          {pos + " / " + total}
        </span>
      ) : null}
      <button
        className="slup__iconBtn"
        onClick={() => jump(-1)}
        disabled={!canJump}
        title="Previous redaction"
        aria-label="Jump to previous redaction"
      >
        <Icon.ChevronUp />
      </button>
      <button
        className="slup__iconBtn"
        onClick={() => jump(1)}
        disabled={!canJump}
        title="Next redaction"
        aria-label="Jump to next redaction"
      >
        <Icon.ChevronDown />
      </button>
      <button
        className="slup__iconBtn"
        onClick={() => api?.toggleSearch()}
        disabled={!api}
        title="Find in the redacted text (Ctrl/Cmd+F). Searches the redacted output, so a value with no matches was fully redacted."
        aria-label="Find in the redacted text"
      >
        <Icon.Search />
      </button>
    </>
  );
}

function Viewer() {
  const flow = useFlow();
  const { reveal, wrap, allowRevealOriginal, urlFor, policy, renderPreview, bindFindKey } = flow;
  const [api, setApi] = useState<PreviewApi | null>(null);
  const f = selectedFile(flow);
  if (!f)
    return (
      <div className="slup__viewer">
        <div className="slup__docFallback">Select a file to preview</div>
      </div>
    );
  const isText = f.det!.kind === "text";
  const isImg = f.det!.kind === "binary" && policy.imageExtensions.has(f.det!.ext);
  const redactionTotal = (f.redactions ?? []).filter((r) => r.outEnd > r.outStart).length;
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
              <span className="slup__toggleLabel">{wrap ? "Wrapping" : "No wrap"}</span>
            </button>
            {allowRevealOriginal ? (
              <button
                className={"slup__toggle" + (reveal ? " slup__toggle--on" : "")}
                onClick={() => flow.setReveal((v) => !v)}
                aria-pressed={reveal}
                title="Local-only. Shows the original values that were replaced."
              >
                {reveal ? <Icon.Eye /> : <Icon.EyeOff />}
                <span className="slup__toggleLabel">
                  {reveal ? "Showing original" : "Reveal original"}
                </span>
              </button>
            ) : null}
            {!renderPreview ? (
              <PreviewToolControls
                key={f.id}
                api={api}
                total={redactionTotal}
                bindFindKey={bindFindKey}
              />
            ) : null}
          </div>
        ) : null}
      </div>
      {isText ? (
        <TextPreview {...redactedArgs(f, flow)} onReady={setApi} />
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
  const [api, setApi] = useState<PreviewApi | null>(null);
  const f = selectedFile(flow);
  if (!f || f.det!.kind !== "text") return <Viewer />;
  const redactionTotal = (f.redactions ?? []).filter((r) => r.outEnd > r.outStart).length;
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
            <span className="slup__toggleLabel">{flow.wrap ? "Wrapping" : "No wrap"}</span>
          </button>
          {!flow.renderPreview ? (
            <PreviewToolControls
              key={f.id}
              api={api}
              total={redactionTotal}
              bindFindKey={flow.bindFindKey}
            />
          ) : null}
          <span className="slup__splitHint">Original → Redacted</span>
        </div>
      </div>
      <div className="slup__split">
        <div className="slup__splitOrig">
          <TextPreview text={f.originalText ?? ""} wrap={flow.wrap} />
        </div>
        <TextPreview {...redactedArgs(f, flow)} onReady={setApi} />
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
            : "Processing locally on your device."}
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

  const distinctValues = summary ? summary.mappingSize : 0;
  const instances = summary
    ? [...summary.usage.values()].reduce((a, u) => a + u.count, 0)
    : 0;
  const catCount = summary ? Object.keys(summary.totals).length : 0;
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

  return (
    <div>
      <Note icon={Icon.ShieldCheck}>
        {distinctValues > 0 ? (
          <>
            Replaced <strong>{plural(distinctValues, "distinct value", "distinct values")}</strong> (
            {plural(instances, "instance", "instances")}) across{" "}
            <strong>{plural(catCount, "category", "categories")}</strong>. Hover any{" "}
            <span className="slup__spark">highlight</span> to see how often it appears and that it
            maps consistently everywhere.
          </>
        ) : (
          "Review the files below before you continue."
        )}
      </Note>
      <Legend />
      <div className="slup__preview" style={{ marginTop: 16 }}>
        <div className="slup__previewList">
          {uploadable.map((f) => {
            const isImg = f.det!.kind === "binary" && policy.imageExtensions.has(f.det!.ext);
            const Comp = f.det!.kind === "text" ? Icon.FileText : isImg ? Icon.Image : Icon.File;
            const redCount = (f.redactions ?? []).filter((r) => r.outEnd > r.outStart).length;
            return (
              <button
                key={f.id}
                className={"slup__pvItem" + (sel === f.id ? " slup__pvItem--active" : "")}
                onClick={() => flow.setSel(f.id)}
              >
                <Comp />
                <span className="slup__pvName" title={f.path}>
                  {redCount > 0 ? (
                    <span className="slup__pvCount" aria-label={`${redCount} redactions`}>
                      ({redCount}){" "}
                    </span>
                  ) : null}
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
