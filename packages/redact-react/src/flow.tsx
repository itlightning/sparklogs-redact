import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { RedactionRecord } from "@sparklogs/redact-core";
import type {
  CategoryDisplay,
  ClassifyPolicy,
  Detection,
  FormFields,
  ProfileName,
  RedactUploadWizardProps,
  UploadFile,
  UploadPayload,
} from "./types.ts";
import { classifyFile, DEFAULT_DOC_EXTS, DEFAULT_IMAGE_EXTS } from "./classify.ts";
import { resolveCategoryMeta } from "./categoryMeta.ts";
import { type RedactionSummary, type UsageEntry } from "./redaction.ts";
import { fromDataTransfer, genRef, uid } from "./util.ts";
import { runRedactionOffThread } from "./worker-runner.ts";
import {
  initConsents,
  toggleConsent as applyConsentToggle,
  validateConsents,
} from "./consent.ts";

const DEFAULT_COPY = {
  railTitle: "Upload logs",
  reasonLabel: "Why are you uploading this data?",
  reasonPlaceholder: "Briefly describe what you're sharing and why.",
  consentTitle: "How may we use this data?",
};

export interface WizardFile {
  id: string;
  file: File;
  name: string;
  path: string;
  size: number;
  det: Detection | null;
  originalText?: string;
  redactedText?: string;
  redactions?: RedactionRecord[];
  stats?: Record<string, number>;
}

interface Tip {
  left: number;
  top: number;
  bottom: number;
  label: string;
  color: string;
  meta: string;
}

export type UploadState = "idle" | "running" | "done" | "error";

const EMPTY_SUMMARY: RedactionSummary = {
  byId: new Map(),
  usage: new Map(),
  totals: {},
  mappingSize: 0,
};

const DEFAULT_PROFILES: ProfileName[] = ["windows-log", "generic", "secret"];

function useUploadFlow(props: RedactUploadWizardProps) {
  const navStyle = props.navStyle ?? "rail";
  const previewStyle = props.previewStyle ?? "inline";
  const allowRevealOriginal = props.allowRevealOriginal ?? true;
  const profiles = props.profiles ?? DEFAULT_PROFILES;
  const createWorker = props.createWorker;
  const consentItems = props.consents;
  const nudgeConfig = props.nudge ?? null;
  const copy = useMemo(() => ({ ...DEFAULT_COPY, ...props.copy }), [props.copy]);

  const policy: ClassifyPolicy = useMemo(
    () => ({
      maxTotalBytes: props.maxTotalBytes ?? 100 * 1024 * 1024,
      maxFiles: props.maxFiles ?? 250,
      imageExtensions: new Set(props.imageExtensions ?? DEFAULT_IMAGE_EXTS),
      docExtensions: new Set(props.docExtensions ?? DEFAULT_DOC_EXTS),
    }),
    [props.maxTotalBytes, props.maxFiles, props.imageExtensions, props.docExtensions],
  );

  const categoryFor = useMemo(
    () => resolveCategoryMeta(props.categoryMeta),
    [props.categoryMeta],
  );

  const [step, setStep] = useState(0);
  const [maxReached, setMaxReached] = useState(0);
  const [files, setFiles] = useState<WizardFile[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [redacting, setRedacting] = useState(false);
  const [redactProgress, setRedactProgress] = useState<{ done: number; total: number } | null>(null);
  const redactAbortRef = useRef<AbortController | null>(null);
  const [summary, setSummary] = useState<RedactionSummary | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [reveal, setReveal] = useState(false);
  const [wrap, setWrap] = useState(true); // text preview soft-wraps long lines by default
  const [tip, setTip] = useState<Tip | null>(null);
  const [form, setForm] = useState<FormFields>(() => ({
    name: "",
    email: "",
    reason: "",
    consents: initConsents(consentItems),
  }));
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [upState, setUpState] = useState<UploadState>("idle");
  const [upError, setUpError] = useState("");
  const [upProgress, setUpProgress] = useState<{ loaded: number; total: number } | null>(null);
  const [refId, setRefId] = useState("");
  const [nudge, setNudge] = useState(false);
  const [nudgeSeen, setNudgeSeen] = useState(false);
  const objUrls = useRef<Record<string, string>>({});
  const abortRef = useRef<AbortController | null>(null);

  const totalSize = files.reduce((s, f) => s + f.size, 0);
  const uploadable = files.filter((f) => f.det && f.det.willUpload);
  const textFiles = files.filter((f) => f.det && f.det.kind === "text");
  const overLimit = totalSize > policy.maxTotalBytes || files.length > policy.maxFiles;

  const goto = useCallback((s: number) => {
    setStep(s);
    setMaxReached((m) => Math.max(m, s));
  }, []);

  // ---- ingest -----------------------------------------------------------
  const addEntries = useCallback(
    async (entries: { file: File; path: string }[]) => {
      const fresh: WizardFile[] = entries.map(({ file, path }) => ({
        id: uid(),
        file,
        name: file.name,
        path,
        size: file.size,
        det: null,
      }));
      setFiles((prev) => {
        const seen = new Set(prev.map((p) => p.path + "|" + p.size));
        const dedup = fresh.filter((f) => !seen.has(f.path + "|" + f.size));
        return prev.concat(dedup);
      });
      for (const f of fresh) {
        try {
          const det = await classifyFile(f.file, policy);
          setFiles((prev) => prev.map((p) => (p.id === f.id ? { ...p, det } : p)));
        } catch {
          /* ignore unreadable files */
        }
      }
    },
    [policy],
  );

  const onPick = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const list = Array.from(e.target.files || []).map((f) => ({
        file: f,
        path: (f as any).webkitRelativePath || f.name,
      }));
      addEntries(list);
      e.target.value = "";
    },
    [addEntries],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      fromDataTransfer(e.dataTransfer).then(addEntries);
    },
    [addEntries],
  );

  const removeFile = useCallback(
    (id: string) => setFiles((prev) => prev.filter((f) => f.id !== id)),
    [],
  );
  const clearAll = useCallback(() => setFiles([]), []);

  // ---- redaction pass ---------------------------------------------------
  // Redaction runs off the main thread (Web Worker) when possible so the UI stays responsive and shows
  // progress; it transparently falls back to a synchronous pass. `originalText` is only fetched when
  // the reveal feature or split preview actually needs it (memory win for large files otherwise).
  const runRedaction = useCallback(async () => {
    const controller = new AbortController();
    redactAbortRef.current = controller;
    setRedacting(true);
    setSummary(null);
    setRedactProgress(null);
    const needsOriginal = allowRevealOriginal || previewStyle === "split";
    try {
      const { summary: result, originals } = await runRedactionOffThread(
        textFiles.map((f) => ({ id: f.id, file: f.file })),
        profiles,
        {
          needsOriginal,
          onProgress: (done, total) => setRedactProgress({ done, total }),
          signal: controller.signal,
          createWorker,
        },
      );
      setFiles((prev) =>
        prev.map((p) => {
          const fr = result.byId.get(p.id);
          if (!fr) return p;
          return {
            ...p,
            originalText: originals[p.id],
            redactedText: fr.text,
            redactions: fr.redactions,
            stats: fr.stats,
          };
        }),
      );
      setSummary(result);
      setSel((cur) => cur ?? uploadable[0]?.id ?? null);
    } catch {
      if (controller.signal.aborted) return; // canceled — cancelRedaction handles navigation
      setSummary(EMPTY_SUMMARY); // defensive: never leave the wizard stuck on the spinner
    } finally {
      if (!controller.signal.aborted) setRedacting(false);
    }
  }, [textFiles, profiles, uploadable, allowRevealOriginal, previewStyle, createWorker]);

  const cancelRedaction = useCallback(() => {
    redactAbortRef.current?.abort();
    setRedacting(false);
    setRedactProgress(null);
    goto(1); // leave the preview step so the auto-run effect doesn't immediately re-trigger
  }, [goto]);

  // auto-run redaction on arrival at the preview step (guarded against loops via a ref)
  const runRef = useRef(runRedaction);
  runRef.current = runRedaction;
  useEffect(() => {
    if (step === 2 && !summary && !redacting) {
      if (textFiles.length) runRef.current();
      else setSummary(EMPTY_SUMMARY);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  // object URLs for image previews
  const urlFor = useCallback((f: WizardFile) => {
    if (!objUrls.current[f.id]) objUrls.current[f.id] = URL.createObjectURL(f.file);
    return objUrls.current[f.id];
  }, []);
  useEffect(
    () => () => {
      Object.values(objUrls.current).forEach(URL.revokeObjectURL);
    },
    [],
  );

  // ---- form -------------------------------------------------------------
  const setFormField = useCallback(
    (key: "name" | "email" | "reason", value: string) => {
      setForm((s) => ({ ...s, [key]: value }));
      setErrs((s) => {
        if (!s[key]) return s;
        const n = { ...s };
        delete n[key];
        return n;
      });
    },
    [],
  );

  // Generic consent dependency: see consent.ts (e.g. community implies product).
  const toggleConsent = useCallback(
    (id: string) => {
      setForm((s) => ({ ...s, consents: applyConsentToggle(s.consents, consentItems, id) }));
      setErrs((s) => {
        if (!s[id]) return s;
        const n = { ...s };
        delete n[id];
        return n;
      });
    },
    [consentItems],
  );

  const validate = useCallback(() => {
    const e: Record<string, string> = {};
    if (!form.name.trim()) e.name = "Name is required";
    if (!form.email.trim()) e.email = "Email is required";
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = "Enter a valid email";
    Object.assign(e, validateConsents(form.consents, consentItems));
    setErrs(e);
    return Object.keys(e).length === 0;
  }, [form, consentItems]);

  // ---- upload -----------------------------------------------------------
  const buildPayload = useCallback((): UploadPayload => {
    const out: UploadFile[] = uploadable.map((f) =>
      f.det!.kind === "text"
        ? { name: f.name, path: f.path, kind: "text", redactedText: f.redactedText, stats: f.stats }
        : { name: f.name, path: f.path, kind: "binary", blob: f.file },
    );
    const s = summary ?? EMPTY_SUMMARY;
    return {
      fields: form,
      files: out,
      summary: { totals: s.totals, mappingSize: s.mappingSize, fileCount: out.length },
    };
  }, [uploadable, summary, form]);

  const startUpload = useCallback(async () => {
    const controller = new AbortController();
    abortRef.current = controller;
    setUpState("running");
    setUpError("");
    setUpProgress(null);
    try {
      const res = await props.onSubmit(buildPayload(), {
        onProgress: (p) => setUpProgress(p),
        signal: controller.signal,
      });
      setRefId((res && "referenceId" in res && res.referenceId) || genRef());
      setUpState("done");
    } catch (err) {
      if (controller.signal.aborted) setUpError("Upload canceled.");
      else setUpError((err as Error)?.message || "Upload failed. Please try again.");
      setUpState("error");
    }
  }, [props, buildPayload]);

  const cancelUpload = useCallback(() => abortRef.current?.abort(), []);

  const proceedToUpload = useCallback(() => {
    setNudge(false);
    goto(4);
    void startUpload();
  }, [goto, startUpload]);

  // ---- navigation gating ------------------------------------------------
  const canNext = useCallback(() => {
    if (step === 0 || step === 1) return uploadable.length > 0 && !overLimit;
    if (step === 2) return !!summary && !redacting;
    if (step === 3) return true; // validated on click
    return false;
  }, [step, uploadable.length, overLimit, summary, redacting]);

  const onNext = useCallback(() => {
    if (step === 3) {
      if (!validate()) return;
      if (nudgeConfig && !form.consents[nudgeConfig.whenUnchecked] && !nudgeSeen) {
        setNudgeSeen(true);
        setNudge(true);
        return;
      }
      proceedToUpload();
      return;
    }
    goto(step + 1);
  }, [step, validate, nudgeConfig, form.consents, nudgeSeen, proceedToUpload, goto]);

  const resetAll = useCallback(() => {
    Object.values(objUrls.current).forEach(URL.revokeObjectURL);
    objUrls.current = {};
    setFiles([]);
    setSummary(null);
    setSel(null);
    setReveal(false);
    setForm({ name: "", email: "", reason: "", consents: initConsents(consentItems) });
    setErrs({});
    setUpState("idle");
    setUpError("");
    setUpProgress(null);
    setRefId("");
    setMaxReached(0);
    setStep(0);
    setNudge(false);
    setNudgeSeen(false);
  }, [consentItems]);

  // ---- tooltip ----------------------------------------------------------
  const showTip = useCallback(
    (e: React.SyntheticEvent, label: string, color: string, meta: string) => {
      const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
      setTip({ left: r.left + r.width / 2, top: r.top, bottom: r.bottom, label, color, meta });
    },
    [],
  );
  const hideTip = useCallback(() => setTip(null), []);

  return {
    // config
    navStyle,
    previewStyle,
    allowRevealOriginal,
    policy,
    categoryFor,
    detailsSlot: props.detailsSlot,
    renderPreview: props.renderPreview,
    consentItems,
    consentGroups: props.consentGroups,
    nudgeConfig,
    copy,
    // state
    step,
    maxReached,
    files,
    dragOver,
    redacting,
    redactProgress,
    summary,
    sel,
    reveal,
    wrap,
    tip,
    form,
    errs,
    upState,
    upError,
    upProgress,
    refId,
    nudge,
    // derived
    totalSize,
    uploadable,
    textFiles,
    overLimit,
    // setters / actions
    setStep,
    setDragOver,
    setSel,
    setReveal,
    setWrap,
    setNudge,
    setForm,
    setFormField,
    toggleConsent,
    goto,
    addEntries,
    onPick,
    onDrop,
    removeFile,
    clearAll,
    urlFor,
    canNext,
    onNext,
    proceedToUpload,
    startUpload,
    cancelUpload,
    cancelRedaction,
    resetAll,
    showTip,
    hideTip,
  };
}

export type Flow = ReturnType<typeof useUploadFlow>;
export type { UsageEntry };

const FlowContext = createContext<Flow | null>(null);

export function FlowProvider({
  props,
  children,
}: {
  props: RedactUploadWizardProps;
  children: React.ReactNode;
}) {
  const flow = useUploadFlow(props);
  return <FlowContext.Provider value={flow}>{children}</FlowContext.Provider>;
}

export function useFlow(): Flow {
  const f = useContext(FlowContext);
  if (!f) throw new Error("useFlow must be used within <RedactUploadWizard>");
  return f;
}

export type { CategoryDisplay };
