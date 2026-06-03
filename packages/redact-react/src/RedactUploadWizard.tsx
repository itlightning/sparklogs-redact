import { useEffect } from "react";
import * as Icon from "./icons.tsx";
import type { RedactUploadWizardProps } from "./types.ts";
import { FlowProvider, useFlow } from "./flow.tsx";
import { FloatingTip } from "./components/shared.tsx";
import { StepSelect } from "./components/StepSelect.tsx";
import { StepReview } from "./components/StepReview.tsx";
import { StepRedact, prefetchCodeMirrorPreview } from "./components/StepRedact.tsx";
import { StepDetails, ConsentModal } from "./components/StepDetails.tsx";
import { StepSend } from "./components/StepSend.tsx";

const STEPS = [
  { label: "Select files", hint: "Drop folders or files" },
  { label: "Review types", hint: "Confirm what we detected" },
  { label: "Redact & preview", hint: "Anonymize, then look" },
  { label: "Your details", hint: "Contact & permissions" },
  { label: "Send", hint: "Upload & confirm" },
];

function Stepper() {
  const { step, maxReached, upState, setStep, copy } = useFlow();
  const locked = upState === "running" || upState === "done";
  return (
    <nav className="slup__rail" aria-label={copy.railTitle}>
      <div className="slup__railTitle">{copy.railTitle}</div>
      <ol className="slup__steps">
        {STEPS.map((s, i) => {
          const state = i < step ? "done" : i === step ? "active" : "upcoming";
          const clickable = i <= maxReached && !locked;
          return (
            <li
              key={i}
              className={
                "slup__step slup__step--" + state + (clickable ? " slup__step--clickable" : "")
              }
              aria-current={state === "active" ? "step" : undefined}
              {...(clickable
                ? {
                    role: "button",
                    tabIndex: 0,
                    onClick: () => setStep(i),
                    onKeyDown: (e: React.KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setStep(i);
                      }
                    },
                  }
                : {})}
            >
              <span className="slup__dot" aria-hidden="true">
                {state === "done" ? <Icon.Check /> : i + 1}
              </span>
              <span className="slup__stepText">
                <span className="slup__stepLabel">{s.label}</span>
                <span className="slup__stepHint">{s.hint}</span>
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

const HEADS = [
  {
    k: "Step 1",
    t: "Add your log files",
    s: "Drop a whole folder or pick individual files. Each one is checked locally before anything is uploaded.",
  },
  {
    k: "Step 2",
    t: "Review what we detected",
    s: "Confirm the read on each file. Text files get PII-redacted; allow-listed images and docs go as-is.",
  },
  {
    k: "Step 3",
    t: "Redact, then preview",
    s: "PII is replaced in-memory across all files at once. Scroll the result and open any screenshot before sending.",
  },
  {
    k: "Step 4",
    t: "Your details & permissions",
    s: "Tell us who you are and how the redacted data may be used.",
  },
  {
    k: "Step 5",
    t: "Sending your redacted files",
    s: "Uploading over TLS. This stays on the page until it finishes.",
  },
];

const BODIES = [StepSelect, StepReview, StepRedact, StepDetails, StepSend];

function Footer() {
  const { step, canNext, onNext, setStep, upState, textFiles } = useFlow();
  if (upState === "running" || upState === "done") return null;
  const footNote =
    step === 0
      ? "Processed locally. Nothing leaves your browser yet."
      : step === 2
        ? textFiles.length
          ? "Redaction runs entirely on your device."
          : "No text files to redact."
        : step === 3
          ? "You can review everything before it sends."
          : "";
  const nextLabel =
    step === 3 ? "Upload redacted data" : step === 2 ? "Looks good, continue" : "Continue";
  const NextIcon = step === 3 ? Icon.Zap : Icon.ChevronRight;
  return (
    <div className="slup__foot">
      {step > 0 ? (
        <button className="slup__btn slup__btn--ghost" onClick={() => setStep(step - 1)}>
          <Icon.ChevronLeft />
          Back
        </button>
      ) : (
        <span className="slup__footNote">{footNote}</span>
      )}
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        {step > 0 ? <span className="slup__footNote">{footNote}</span> : null}
        <button className="slup__btn slup__btn--primary" disabled={!canNext()} onClick={onNext}>
          {nextLabel}
          <NextIcon />
        </button>
      </div>
    </div>
  );
}

function WizardShell() {
  const { step, navStyle, nudge } = useFlow();
  const Body = BODIES[step];
  const h = HEADS[step];
  return (
    <div className={"slup slup--" + navStyle}>
      <div className="slup__shell">
        <Stepper />
        <section className="slup__main">
          <header className="slup__head">
            <div className="slup__kicker">{h.k}</div>
            <h1 className="slup__title">{h.t}</h1>
            <p className="slup__sub">{h.s}</p>
          </header>
          <div className="slup__body">
            <Body />
          </div>
          <Footer />
        </section>
      </div>
      {nudge ? <ConsentModal /> : null}
      <FloatingTip />
    </div>
  );
}

/**
 * In-browser "redact locally, then upload" wizard. Classifies files, redacts PII with
 * @sparklogs/redact-core, previews the before/after, and hands a redacted {@link UploadPayload} to
 * the host's `onSubmit`. Import the stylesheet once: `import "@sparklogs/redact-react/styles.css"`.
 */
export function RedactUploadWizard(props: RedactUploadWizardProps) {
  // Warm the lazy CodeMirror preview chunk right after first paint (during idle time), so it's loaded
  // by the time the user reaches the preview step without delaying the wizard's initial render. Skipped
  // when the host renders its own preview, since CodeMirror is then never used.
  const hasCustomPreview = !!props.renderPreview;
  useEffect(() => {
    if (hasCustomPreview) return;
    // `requestIdleCallback` isn't in every engine (e.g. older Safari), so feature-detect via a plain
    // optional-shaped view of `window` rather than the DOM lib's non-optional declaration.
    const w = window as unknown as {
      requestIdleCallback?: (cb: () => void) => number;
      cancelIdleCallback?: (id: number) => void;
    };
    const id = w.requestIdleCallback
      ? w.requestIdleCallback(prefetchCodeMirrorPreview)
      : window.setTimeout(prefetchCodeMirrorPreview, 200);
    return () => {
      if (w.requestIdleCallback && w.cancelIdleCallback) w.cancelIdleCallback(id);
      else window.clearTimeout(id);
    };
  }, [hasCustomPreview]);

  return (
    <FlowProvider props={props}>
      <WizardShell />
    </FlowProvider>
  );
}
