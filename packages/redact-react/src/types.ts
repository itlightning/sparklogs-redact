import type { ReactNode } from "react";
import type { RedactionRecord } from "@sparklogs/redact-core";

/**
 * Args passed to a custom `renderPreview`. The default preview is a virtualized CodeMirror 6 viewer
 * that highlights each redaction range (`outStart`/`outEnd`) and, when `reveal` is set, shows the
 * original token sliced from `originalText` via the input offsets.
 */
export interface PreviewRenderArgs {
  /** The text to render (redacted text for the right pane; original for the split left pane). */
  text: string;
  /** Redaction records to highlight; omit for a plain (un-highlighted) document. */
  redactions?: RedactionRecord[];
  /** Original decoded text (present only when reveal/split need it). */
  originalText?: string;
  /** Whether to reveal originals in place of the fakes. */
  reveal?: boolean;
  /** Soft-wrap long lines (default true). When false, the viewer scrolls horizontally instead. */
  wrap?: boolean;
  /** Resolve a category's display (label/color). */
  categoryFor?: (category: string) => CategoryDisplay;
  /** Cross-file usage aggregate, keyed by replacement, for hover metadata. */
  usage?: Map<string, { replacement: string; category: string; count: number; files: Set<string> }>;
  /**
   * Called when the viewer mounts (with an imperative {@link PreviewApi}) and on unmount (with null).
   * The default CodeMirror viewer provides one so the toolbar can drive jump-to-redaction and the
   * search panel; a custom preview may omit it (those controls then hide).
   */
  onReady?: (api: PreviewApi | null) => void;
}

/**
 * Imperative handle a preview can expose via {@link PreviewRenderArgs.onReady} so the toolbar (and the
 * Ctrl/Cmd+F binding) can drive it. All operations target this preview's own document.
 */
export interface PreviewApi {
  /** Number of highlightable redactions in the current document. */
  redactionCount: number;
  /** Move the cursor to the next (`1`) / previous (`-1`) redaction and scroll it into view. Returns the
   * new 1-based position, or 0 when there are none. Wraps around the ends. */
  gotoRedaction: (dir: 1 | -1) => number;
  /** Open the find panel (if closed) and focus + select its query field. */
  openSearch: () => void;
  /** Toggle the find panel open/closed (focusing the field when opening). */
  toggleSearch: () => void;
}

/** Built-in @sparklogs/redact-core detection profiles this wizard can compose. */
export type ProfileName = "windows-log" | "generic" | "secret";

/** How a redaction category is displayed (label/color/description). */
export interface CategoryDisplay {
  label: string;
  /** Any CSS color, typically a `var(--slup-cat-*)` reference. */
  color: string;
  desc: string;
}

/** File-acceptance policy (size caps + allow-listed binary extensions). */
export interface ClassifyPolicy {
  maxTotalBytes: number;
  maxFiles: number;
  imageExtensions: Set<string>;
  docExtensions: Set<string>;
}

export type FileKind = "text" | "binary" | "rejected";

/** Result of classifying a single file by sniffing its leading bytes. */
export interface Detection {
  kind: FileKind;
  /** Human-readable encoding label, e.g. "UTF-8", "UTF-16 LE", or "binary". */
  encoding: string;
  ext: string;
  reason: string;
  willUpload: boolean;
  willRedact: boolean;
  previewable: boolean;
  isImage: boolean;
}

/** A host-defined consent checkbox. The component renders/validates these generically. */
export interface ConsentItem {
  id: string;
  label: string;
  desc: string;
  /** Must be checked to proceed. */
  required?: boolean;
  /** "primary" renders ungrouped; "optional" renders inside the optional group. */
  group: "primary" | "optional";
  /**
   * Dependency: checking this also checks every id listed here; unchecking any listed id also
   * unchecks this (transitively). e.g. a "community" item that implies ["product"].
   */
  implies?: string[];
}

/** Presentation of the optional consent group. */
export interface ConsentGroupsConfig {
  optionalHeading?: string;
  optionalTag?: string;
  note?: ReactNode;
}

/** A one-time pre-submit nudge shown when an optional consent is left unchecked. Omit/null = none. */
export interface NudgeConfig {
  /** Show the nudge on "continue" when this consent id is unchecked (once per session). */
  whenUnchecked: string;
  title: string;
  body: ReactNode;
  reassurance?: ReactNode;
  acceptLabel: string;
  declineLabel: string;
  cancelLabel?: string;
  /** Consent id to switch on when the user accepts the nudge. */
  acceptSetsConsent?: string;
}

/** Overridable strings (everything else has generic defaults). */
export interface CopyConfig {
  railTitle: string;
  reasonLabel: string;
  reasonPlaceholder: string;
  consentTitle: string;
}

export interface FormFields {
  name: string;
  email: string;
  reason: string;
  /** Consent id → checked. */
  consents: Record<string, boolean>;
}

/** Passed to the host's onSubmit so it can stream progress + observe cancellation. */
export interface UploadContext {
  /** Report cumulative upload progress (bytes) so the wizard renders a determinate bar. */
  onProgress: (p: { loaded: number; total: number }) => void;
  /** Aborts when the user clicks Cancel; the host must abort its in-flight transport. */
  signal: AbortSignal;
}

/** One file in the payload handed to the host's onSubmit. */
export interface UploadFile {
  name: string;
  path: string;
  kind: "text" | "binary";
  /** Present for text files: the redacted content (safe to upload). */
  redactedText?: string;
  /** Present for binary files: the original blob (uploaded as-is, never redacted). */
  blob?: Blob;
  /** Per-category replacement counts for text files. */
  stats?: Record<string, number>;
}

/** The complete, already-redacted payload the host transmits. */
export interface UploadPayload {
  fields: FormFields;
  files: UploadFile[];
  summary: {
    /** Distinct values redacted per category, across all files. */
    totals: Record<string, number>;
    /** Total distinct values redacted. */
    mappingSize: number;
    fileCount: number;
    /** Final enabled state per redaction category (locked categories are always true). */
    redactRules: Record<string, boolean>;
  };
}

export interface RedactUploadWizardProps {
  /**
   * Transmit the redacted payload. The host owns the network call and any extra fields (e.g. a
   * captcha token). `ctx.onProgress` lets the host stream upload progress to the wizard's bar, and
   * `ctx.signal` aborts when the user cancels. Resolve with a `referenceId` to show it on the
   * confirmation screen; reject to surface an error and let the user retry.
   */
  onSubmit: (payload: UploadPayload, ctx: UploadContext) => Promise<{ referenceId?: string } | void>;
  /**
   * Host-rendered content placed inside the "Your details" step — e.g. a Cloudflare Turnstile widget.
   * The component does not read it; the host wires whatever it renders here into `onSubmit`.
   */
  detailsSlot?: ReactNode;
  /** Consent checkboxes shown in the details step (host-defined; component renders + validates them). */
  consents: ConsentItem[];
  /** Presentation of the optional consent group. */
  consentGroups?: ConsentGroupsConfig;
  /** Optional one-time pre-submit nudge. Omit or pass null to skip the nudge entirely. */
  nudge?: NudgeConfig | null;
  /** Override a handful of strings; everything else has generic defaults. */
  copy?: Partial<CopyConfig>;
  /** Max combined size of selected files (bytes). Default 100 MB. */
  maxTotalBytes?: number;
  /** Max number of selected files. Default 250. */
  maxFiles?: number;
  /** Allow-listed image extensions (lowercase, no dot). Uploaded as-is, not redacted. */
  imageExtensions?: string[];
  /** Allow-listed document extensions (lowercase, no dot). Uploaded as-is, not redacted. */
  docExtensions?: string[];
  /**
   * Escape hatch for constructing the redaction Web Worker if your bundler needs specific syntax. The
   * component bundles + instantiates its own worker by default, and falls back to a synchronous
   * in-thread pass if a worker can't be created, so this is rarely needed.
   */
  createWorker?: () => Worker;
  /**
   * Override the text preview. By default the component lazy-loads a virtualized CodeMirror 6 viewer.
   * Provide this to render your own (e.g. to drop the CodeMirror dependency).
   */
  renderPreview?: (args: PreviewRenderArgs) => ReactNode;
  /** Which detection profiles to compose. Default: all three. */
  profiles?: ProfileName[];
  /** Stepper layout. Default "rail". */
  navStyle?: "rail" | "top";
  /** Redaction preview layout. Default "inline". */
  previewStyle?: "inline" | "split";
  /**
   * Whether the text preview soft-wraps long lines by default. Default false — unwrapped lines keep a
   * uniform height, so the preview's scrollbar stays steady on large files (wrapping makes CodeMirror
   * estimate wrap-counts on demand, which jiggles the scrollbar). Users can still toggle wrap per file.
   */
  defaultWrap?: boolean;
  /**
   * Allow the local-only "reveal original" toggle in the preview. The original values are read from
   * the in-browser file text and never transmitted. Default true.
   */
  allowRevealOriginal?: boolean;
  /**
   * Which discretionary redaction categories the user may toggle (in the "Customize redaction rules"
   * panel), keyed by category with each one's DEFAULT enabled state. Categories absent here — and the
   * always-on locked set (creditcard, ssn, email, secret, token) — are always redacted and not
   * customizable. Defaults to a sensible discretionary set (see `DEFAULT_REDACTION_RULES`).
   */
  redactionRules?: Record<string, boolean>;
  /** Show the "Customize redaction rules" panel in the review step. Default true. */
  allowRuleCustomization?: boolean;
  /**
   * While the preview step is active, bind Ctrl/Cmd+F to open the preview's find panel (instead of the
   * browser's native find, which can't see the virtualized text). Default true; set false to leave the
   * native find shortcut alone.
   */
  bindFindKey?: boolean;
  /** Override category display (label/color/desc) by redact-core category key. */
  categoryMeta?: Record<string, Partial<CategoryDisplay>>;
}
