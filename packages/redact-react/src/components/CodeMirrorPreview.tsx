// Virtualized (viewport-only) read-only preview built on CodeMirror 6. Renders the redacted text and
// decorates each redaction range from its output offsets — mark decorations for the fakes, or
// replace-widgets showing the original token when `reveal` is on. Lazy-loaded by StepRedact so the
// CodeMirror dependency only loads at the preview step.
import { useEffect, useRef } from "react";
import { Compartment, EditorState } from "@codemirror/state";
import { Decoration, EditorView, WidgetType, type DecorationSet } from "@codemirror/view";
import type { PreviewRenderArgs } from "../types.ts";

const FALLBACK_CATEGORY = { label: "Redacted", color: "var(--slup-accent)", desc: "" };

class OriginalWidget extends WidgetType {
  constructor(
    readonly original: string,
    readonly color: string,
    // When revealing, the pill shows the original token but the tooltip still describes the
    // replacement ("Maps to <fake> everywhere…") — that mapping is the useful thing to surface here.
    readonly title: string,
  ) {
    super();
  }
  eq(other: OriginalWidget) {
    return (
      other.original === this.original &&
      other.color === this.color &&
      other.title === this.title
    );
  }
  toDOM() {
    const span = document.createElement("span");
    span.className = "slup-cm-pill slup-cm-pill--revealed";
    span.style.setProperty("--pc", this.color);
    span.title = this.title;
    span.setAttribute("aria-label", this.title);
    span.textContent = this.original;
    return span;
  }
}

function buildDecorations(args: PreviewRenderArgs): DecorationSet {
  const { redactions, originalText, reveal, categoryFor, usage } = args;
  if (!redactions || redactions.length === 0) return Decoration.none;
  const cat = categoryFor ?? (() => FALLBACK_CATEGORY);
  const ranges = [];
  const sorted = [...redactions].sort((a, b) => a.outStart - b.outStart);
  for (const r of sorted) {
    if (r.outStart >= r.outEnd) continue;
    const meta = cat(r.category);
    const u = usage?.get(r.replacement);
    const title = u
      ? `${meta.label}. Maps to ${r.replacement} everywhere. Appears ${u.count}× across ${u.files.size} file${u.files.size > 1 ? "s" : ""}.`
      : meta.label;
    if (reveal && originalText != null) {
      ranges.push(
        Decoration.replace({
          widget: new OriginalWidget(originalText.slice(r.start, r.end), meta.color, title),
        }).range(r.outStart, r.outEnd),
      );
    } else {
      ranges.push(
        Decoration.mark({
          class: "slup-cm-pill",
          attributes: { style: `--pc: ${meta.color}`, title, "aria-label": title },
        }).range(r.outStart, r.outEnd),
      );
    }
  }
  return Decoration.set(ranges, true);
}

const baseTheme = EditorView.theme({
  "&": { backgroundColor: "transparent", color: "var(--slup-text-2)", height: "100%" },
  ".cm-scroller": {
    fontFamily: "var(--slup-font-mono)",
    fontSize: "0.82rem",
    lineHeight: "1.65",
    overflow: "auto",
  },
  ".cm-content": { padding: "16px 18px" },
  ".cm-gutters": { display: "none" },
  "&.cm-focused": { outline: "none" },
  ".cm-selectionBackground, ::selection": {
    backgroundColor: "color-mix(in srgb, var(--slup-accent) 28%, transparent)",
  },
});

export default function CodeMirrorPreview(args: PreviewRenderArgs) {
  const parentRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const decoCompartment = useRef(new Compartment());
  const wrapCompartment = useRef(new Compartment());

  // Create the editor once.
  useEffect(() => {
    if (!parentRef.current) return;
    const view = new EditorView({
      parent: parentRef.current,
      state: EditorState.create({
        doc: args.text,
        extensions: [
          EditorState.readOnly.of(true),
          EditorView.editable.of(false),
          wrapCompartment.current.of(args.wrap === false ? [] : EditorView.lineWrapping),
          baseTheme,
          decoCompartment.current.of(EditorView.decorations.of(buildDecorations(args))),
        ],
      }),
    });
    viewRef.current = view;
    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Apply doc + decoration changes together so decorations always match the current document.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const textChanged = view.state.doc.toString() !== args.text;
    view.dispatch({
      changes: textChanged
        ? { from: 0, to: view.state.doc.length, insert: args.text }
        : undefined,
      effects: decoCompartment.current.reconfigure(
        EditorView.decorations.of(buildDecorations(args)),
      ),
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [args.text, args.redactions, args.reveal, args.originalText, args.usage, args.categoryFor]);

  // Toggle soft line-wrap independently so it never forces a decoration rebuild.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    view.dispatch({
      effects: wrapCompartment.current.reconfigure(
        args.wrap === false ? [] : EditorView.lineWrapping,
      ),
    });
  }, [args.wrap]);

  return <div ref={parentRef} className="slup__cm" />;
}
