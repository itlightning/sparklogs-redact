import type { ReactNode } from "react";
import * as Icon from "../icons.tsx";
import { useFlow } from "../flow.tsx";
import type { ConsentItem } from "../types.ts";

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
  const val = form[name];
  const cls =
    (area ? "slup__textarea" : "slup__input") +
    (errs[name] ? (area ? " slup__textarea--err" : " slup__input--err") : "");
  return (
    <div className="slup__field">
      <label className="slup__label">
        {label}
        {required ? <span className="slup__req">*</span> : null}
      </label>
      <div className="slup__inputWrap">
        <IconComp />
        {area ? (
          <textarea
            className={cls}
            value={val}
            placeholder={placeholder}
            onChange={(e) => setFormField(name, e.target.value)}
          />
        ) : (
          <input
            type={type}
            className={cls}
            value={val}
            placeholder={placeholder}
            onChange={(e) => setFormField(name, e.target.value)}
          />
        )}
      </div>
      {errs[name] ? (
        <div className="slup__errMsg">
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
          <div className="slup__errMsg" style={{ marginTop: 6 }}>
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
  if (!nudgeConfig) return null;
  const accept = () => {
    if (nudgeConfig.acceptSetsConsent && !form.consents[nudgeConfig.acceptSetsConsent]) {
      toggleConsent(nudgeConfig.acceptSetsConsent);
    }
    proceedToUpload();
  };
  return (
    <div className="slup__modalOverlay" onClick={() => setNudge(false)}>
      <div
        className="slup__modal"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="slup__modalIcon">
          <Icon.Zap />
        </div>
        <h3 className="slup__modalTitle">{nudgeConfig.title}</h3>
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
