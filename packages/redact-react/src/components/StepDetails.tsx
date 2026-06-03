import { useCallback, useEffect, useId, useRef, type ReactNode } from "react";
import * as Icon from "../icons.tsx";
import { useFlow } from "../flow.tsx";
import type { ConsentItem } from "../types.ts";

const FOCUSABLE =
  'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

function Field({
  name,
  label,
  type,
  placeholder,
  icon: IconComp,
  required,
  area,
}: {
  name: "name" | "email" | "reason";
  label: string;
  type?: string;
  placeholder: string;
  icon: (p: any) => ReactNode;
  required?: boolean;
  area?: boolean;
}) {
  const { form, errs, setFormField } = useFlow();
  const fieldId = useId();
  const errId = `${fieldId}-err`;
  const val = form[name];
  const invalid = !!errs[name];
  const cls =
    (area ? "slup__textarea" : "slup__input") +
    (invalid ? (area ? " slup__textarea--err" : " slup__input--err") : "");
  const shared = {
    id: fieldId,
    name,
    className: cls,
    value: val,
    placeholder,
    "aria-required": required || undefined,
    "aria-invalid": invalid || undefined,
    "aria-describedby": invalid ? errId : undefined,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      setFormField(name, e.target.value),
  };
  return (
    <div className="slup__field">
      <label className="slup__label" htmlFor={fieldId}>
        {label}
        {required ? (
          <span className="slup__req" aria-hidden="true">
            *
          </span>
        ) : null}
      </label>
      <div className="slup__inputWrap">
        <IconComp />
        {area ? <textarea {...shared} /> : <input type={type} {...shared} />}
      </div>
      {invalid ? (
        <div className="slup__errMsg" id={errId} role="alert">
          <Icon.Alert />
          {errs[name]}
        </div>
      ) : null}
    </div>
  );
}

function Consent({ item }: { item: ConsentItem }) {
  const { form, errs, toggleConsent } = useFlow();
  const on = form.consents[item.id];
  return (
    <label className={"slup__consent" + (on ? " slup__consent--on" : "")}>
      <input
        type="checkbox"
        className="slup__consentNativeInput"
        checked={on}
        onChange={() => toggleConsent(item.id)}
      />
      <span className="slup__check" aria-hidden="true">
        <Icon.Check />
      </span>
      <div>
        <div>
          <span className="slup__consentName">{item.label}</span>
          {item.required ? <span className="slup__consentReq">Required</span> : null}
        </div>
        <div className="slup__consentDesc">{item.desc}</div>
        {errs[item.id] ? (
          <div className="slup__errMsg" style={{ marginTop: 6 }} role="alert">
            <Icon.Alert />
            {errs[item.id]}
          </div>
        ) : null}
      </div>
    </label>
  );
}

export function StepDetails() {
  const { detailsSlot, consentItems, consentGroups, copy } = useFlow();
  const primary = consentItems.filter((c) => c.group === "primary");
  const optional = consentItems.filter((c) => c.group === "optional");
  return (
    <div>
      <Field name="name" label="Name" type="text" placeholder="Your name" icon={Icon.User} required />
      <Field
        name="email"
        label="Email"
        type="email"
        placeholder="you@company.com"
        icon={Icon.Mail}
        required
      />
      <Field
        name="reason"
        label={copy.reasonLabel}
        placeholder={copy.reasonPlaceholder}
        icon={Icon.Message}
        area
      />
      {consentItems.length ? (
        <div className="slup__field">
          <div className="slup__consentTitle">{copy.consentTitle}</div>
          {primary.length ? (
            <div className="slup__consents">
              {primary.map((c) => (
                <Consent key={c.id} item={c} />
              ))}
            </div>
          ) : null}
          {optional.length ? (
            <div className="slup__optGroup">
              {consentGroups?.optionalHeading || consentGroups?.optionalTag ? (
                <div className="slup__optGroupHead">
                  {consentGroups?.optionalTag ? (
                    <span className="slup__optGroupTag">{consentGroups.optionalTag}</span>
                  ) : null}
                  {consentGroups?.optionalHeading}
                </div>
              ) : null}
              <div className="slup__consents">
                {optional.map((c) => (
                  <Consent key={c.id} item={c} />
                ))}
              </div>
              {consentGroups?.note ? (
                <p className="slup__optGroupNote">
                  <Icon.ShieldCheck />
                  <span>{consentGroups.note}</span>
                </p>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
      {detailsSlot ? <div className="slup__field">{detailsSlot}</div> : null}
    </div>
  );
}

export function ConsentModal() {
  const { nudgeConfig, form, toggleConsent, setNudge, proceedToUpload } = useFlow();
  const titleId = useId();
  const modalRef = useRef<HTMLDivElement>(null);
  const close = useCallback(() => setNudge(false), [setNudge]);

  // Focus management: focus into the dialog on open, trap Tab within it, close on Escape, and restore
  // focus to the trigger on unmount.
  useEffect(() => {
    const node = modalRef.current;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const focusables = () =>
      node ? Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE)) : [];
    (focusables()[0] ?? node)?.focus();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        close();
        return;
      }
      if (e.key !== "Tab") return;
      const items = focusables();
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previouslyFocused?.focus?.();
    };
  }, [close]);

  if (!nudgeConfig) return null;
  const accept = () => {
    if (nudgeConfig.acceptSetsConsent && !form.consents[nudgeConfig.acceptSetsConsent]) {
      toggleConsent(nudgeConfig.acceptSetsConsent);
    }
    proceedToUpload();
  };
  return (
    <div className="slup__modalOverlay" onClick={close}>
      <div
        ref={modalRef}
        className="slup__modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="slup__modalIcon" aria-hidden="true">
          <Icon.Zap />
        </div>
        <h3 className="slup__modalTitle" id={titleId}>
          {nudgeConfig.title}
        </h3>
        <p className="slup__modalBody">{nudgeConfig.body}</p>
        {nudgeConfig.reassurance ? (
          <p className="slup__modalReassure">
            <Icon.ShieldCheck />
            <span>{nudgeConfig.reassurance}</span>
          </p>
        ) : null}
        <div className="slup__modalBtns">
          <button className="slup__btn slup__btn--primary" onClick={accept}>
            <Icon.Check />
            {nudgeConfig.acceptLabel}
          </button>
          <button className="slup__btn slup__btn--ghost" onClick={proceedToUpload}>
            {nudgeConfig.declineLabel}
          </button>
        </div>
        <button
          className="slup__btn slup__btn--quiet slup__modalCancel"
          onClick={() => setNudge(false)}
        >
          {nudgeConfig.cancelLabel ?? "Cancel"}
        </button>
      </div>
    </div>
  );
}
