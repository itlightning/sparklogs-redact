// Virtualized (viewport-only) read-only preview built on CodeMirror 6. Renders the redacted text and
// decorates each redaction range from its output offsets — mark decorations for the fakes, or
// replace-widgets showing the original token when `reveal` is on. Lazy-loaded by StepRedact so the
// CodeMirror dependency only loads at the preview step. Exposes an imperative PreviewApi (via
// `onReady`) so the toolbar can jump between redactions and open the find panel.
import { useEffect, useRef } from "react";
import { Compartment, EditorSelection, EditorState, Text } from "@codemirror/state";
import { Decoration, EditorView, WidgetType, keymap, type DecorationSet } from "@codemirror/view";
import {
  closeSearchPanel,
  openSearchPanel,
  search,
  searchKeymap,
  searchPanelOpen,
} from "@codemirror/search";
import type { PreviewApi, PreviewRenderArgs } from "../types.ts";

const FALLBACK_CATEGORY = { label: "Redacted", color: "var(--slup-accent)", desc: "" };

class OriginalWidget extends WidgetType {
  constructor(
    readonly original: string,
    readonly color: string,
    // When revealing, the pill shows the original token but the tooltip still describes the
    // replacement ("Maps to <fake> everywhere…") — that mapping is the useful thing to surface here.
    readonly title: string,
    readonly active: boolean,
  ) {
    super();
  }
  eq(other: OriginalWidget) {
    return (
      other.original === this.original &&
      other.color === this.color &&
      other.title === this.title &&
      other.active === this.active
    );
  }
  toDOM() {
    const span = document.createElement("span");
    span.className = "slup-cm-pill slup-cm-pill--revealed" + (this.active ? " slup-cm-pill--active" : "");
    span.style.setProperty("--pc", this.color);
    span.title = this.title;
    span.setAttribute("aria-label", this.title);
    span.textContent = this.original;
    return span;
  }
}

/** Build the redaction decorations. `activePos` (the output offset of the jumped-to redaction) marks
 *  that one as the current highlight. */
function buildDecorations(args: PreviewRenderArgs, activePos: number | null = null): DecorationSet {
  const { redactions, originalText, reveal, categoryFor, usage } = args;
  if (!redactions || redactions.length === 0) return Decoration.none;
  const cat = categoryFor ?? (() => FALLBACK_CATEGORY);
  const ranges = [];
  const sorted = [...redactions].sort((a, b) => a.outStart - b.outStart);
  for (const r of sorted) {
    if (r.outStart >= r.outEnd) continue;
    const meta = cat(r.category);
    const isActive = activePos != null && r.outStart === activePos;
    const u = usage?.get(r.replacement);
    const title = u
      ? `${meta.label}. Maps to ${r.replacement} everywhere. Appears ${u.count}× across ${u.files.size} file${u.files.size > 1 ? "s" : ""}.`
      : meta.label;
    if (reveal && originalText != null) {
      ranges.push(
        Decoration.replace({
          widget: new OriginalWidget(originalText.slice(r.start, r.end), meta.color, title, isActive),
        }).range(r.outStart, r.outEnd),
      );
    } else {
      ranges.push(
        Decoration.mark({
          class: "slup-cm-pill" + (isActive ? " slup-cm-pill--active" : ""),
          attributes: { style: `--pc: ${meta.color}`, title, "aria-label": title },
        }).range(r.outStart, r.outEnd),
      );
    }
  }
  return Decoration.set(ranges, true);
}

/**
 * Build a CM document that preserves the EXACT text. Passing a raw string to CodeMirror strips the
 * `\r` from CRLF line endings (Windows logs), which would shift every redaction offset after it and
 * eventually push a jump target past the (shortened) document. Splitting on `\n` and using `Text.of`
 * keeps the `\r` as line content, so the document length matches the redaction offsets.
 */
function docOf(text: string): Text {
  return Text.of(text.split("\n"));
}

/** Sorted output-offset start positions for the highlightable redactions — the jump targets. */
function redactionStarts(redactions: PreviewRenderArgs["redactions"]): number[] {
  if (!redactions) return [];
  return redactions
    .filter((r) => r.outEnd > r.outStart)
    .map((r) => r.outStart)
    .sort((a, b) => a - b);
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
  // Find panel (from @codemirror/search), themed to match and made find-only (editor is read-only).
  ".cm-panels": {
    backgroundColor: "var(--slup-surface-raised)",
    color: "var(--slup-text-2)",
    fontFamily: "var(--slup-font-sans)",
  },
  ".cm-panels.cm-panels-top": { borderBottom: "1px solid var(--slup-border)" },
  ".cm-search": {
    padding: "8px 12px",
    display: "flex",
    flexWrap: "wrap",
    alignItems: "center",
    gap: "6px",
    fontSize: "0.78rem",
  },
  ".cm-search label": {
    display: "inline-flex",
    alignItems: "center",
    gap: "4px",
    color: "var(--slup-text-muted)",
  },
  ".cm-search .cm-textfield": {
    backgroundColor: "var(--slup-surface)",
    color: "var(--slup-text)",
    border: "1px solid var(--slup-border)",
    borderRadius: "6px",
    padding: "3px 8px",
  },
  ".cm-search .cm-button": {
    backgroundColor: "transparent",
    backgroundImage: "none",
    color: "var(--slup-text-2)",
    border: "1px solid var(--slup-border)",
    borderRadius: "99px",
    padding: "3px 10px",
    cursor: "pointer",
  },
  ".cm-search .cm-button:hover": {
    backgroundColor: "color-mix(in srgb, var(--slup-accent) 12%, transparent)",
  },
  // Hide the replace row — it can't do anything on a read-only document.
  ".cm-search br": { display: "none" },
  '.cm-search input[name="replace"]': { display: "none" },
  '.cm-search button[name="replace"]': { display: "none" },
  '.cm-search button[name="replaceAll"]': { display: "none" },
});

export default function CodeMirrorPreview(args: PreviewRenderArgs) {
  const parentRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const decoCompartment = useRef(new Compartment());
  const wrapCompartment = useRef(new Compartment());
  // Jump-to-redaction state: sorted target positions, the index we last moved to, and the output
  // offset of the currently-highlighted ("active") redaction.
  const startsRef = useRef<number[]>([]);
  const jumpIdxRef = useRef(-1);
  const activePosRef = useRef<number | null>(null);
  // Keep the latest args + onReady so the create-once effect (and its imperative API) always read the
  // current values rather than the mount-time closure.
  const argsRef = useRef(args);
  argsRef.current = args;
  const onReadyRef = useRef(args.onReady);
  onReadyRef.current = args.onReady;

  // Create the editor once, and publish the imperative API.
  useEffect(() => {
    if (!parentRef.current) return;
    const view = new EditorView({
      parent: parentRef.current,
      state: EditorState.create({
        doc: docOf(args.text),
        extensions: [
          EditorState.readOnly.of(true),
          EditorView.editable.of(false),
          wrapCompartment.current.of(args.wrap === false ? [] : EditorView.lineWrapping),
          search({ top: true }),
          keymap.of(searchKeymap),
          baseTheme,
          decoCompartment.current.of(EditorView.decorations.of(buildDecorations(args))),
        ],
      }),
    });
    viewRef.current = view;
    startsRef.current = redactionStarts(args.redactions);

    const focusSearchField = () => {
      const input = view.dom.querySelector<HTMLInputElement>('.cm-search input[name="search"]');
      if (input) {
        input.focus();
        input.select();
      }
    };
    const openSearch = () => {
      if (!searchPanelOpen(view.state)) openSearchPanel(view);
      // Let a freshly-mounted panel attach before focusing its field.
      requestAnimationFrame(focusSearchField);
    };
    const api: PreviewApi = {
      get redactionCount() {
        return startsRef.current.length;
      },
      gotoRedaction(dir) {
        const starts = startsRef.current;
        if (!starts.length) {
          jumpIdxRef.current = -1;
          activePosRef.current = null;
          return 0;
        }
        let i = jumpIdxRef.current + (dir > 0 ? 1 : -1);
        if (i < 0) i = starts.length - 1;
        if (i >= starts.length) i = 0;
        jumpIdxRef.current = i;
        const target = starts[i]!;
        activePosRef.current = target;
        // Clamp defensively so a stale/out-of-range offset can never throw "selection outside document".
        const pos = Math.min(target, view.state.doc.length);
        view.dispatch({
          selection: EditorSelection.cursor(pos),
          effects: [
            EditorView.scrollIntoView(pos, { y: "center" }),
            // Re-mark decorations so the jumped-to redaction gets the active highlight.
            decoCompartment.current.reconfigure(
              EditorView.decorations.of(buildDecorations(argsRef.current, target)),
            ),
          ],
        });
        // NB: no view.focus() here — focusing the editor would scroll the surrounding page to it; the
        // scrollIntoView effect already moves the preview's own viewport.
        return i + 1;
      },
      openSearch,
      toggleSearch() {
        if (searchPanelOpen(view.state)) closeSearchPanel(view);
        else openSearch();
      },
    };
    onReadyRef.current?.(api);

    return () => {
      onReadyRef.current?.(null);
      view.destroy();
      viewRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Apply doc + decoration changes together so decorations always match the current document, and
  // refresh the jump targets. Switching files (text changes) resets the jump cursor.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const textChanged = view.state.doc.toString() !== args.text;
    // Switching files clears the jump cursor + active highlight.
    if (textChanged) {
      jumpIdxRef.current = -1;
      activePosRef.current = null;
    }
    // For decoration-only changes (e.g. toggling reveal), keep the same line pinned at the top of the
    // viewport — mark vs. replace-widget layout differs, so the scroll would otherwise jump.
    let anchor: number | null = null;
    if (!textChanged) {
      const r = view.scrollDOM.getBoundingClientRect();
      anchor = view.posAtCoords({ x: r.left + 6, y: r.top + 6 });
    }
    view.dispatch({
      changes: textChanged
        ? { from: 0, to: view.state.doc.length, insert: docOf(args.text) }
        : undefined,
      effects: [
        decoCompartment.current.reconfigure(
          EditorView.decorations.of(buildDecorations(args, activePosRef.current)),
        ),
        ...(anchor != null ? [EditorView.scrollIntoView(anchor, { y: "start" })] : []),
      ],
    });
    startsRef.current = redactionStarts(args.redactions);
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
