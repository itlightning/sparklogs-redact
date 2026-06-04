import { useState } from "react";
import * as Icon from "../icons.tsx";
import { useFlow } from "../flow.tsx";
import { FileRow, Note } from "./shared.tsx";

/**
 * Collapsible "Customize redaction rules" panel: a toggle pill per redaction category. Customizable
 * categories flip on/off (and re-redact on the preview step); locked/always-on categories show a lock.
 * Hidden entirely when `allowRuleCustomization` is false or nothing is customizable.
 */
function RedactRulesPanel() {
  const { ruleConfig, enabledCategories, toggleCategory, categoryFor } = useFlow();
  const [open, setOpen] = useState(false);
  if (!ruleConfig.some((r) => r.customizable)) return null;
  const onCount = ruleConfig.filter((r) => enabledCategories.has(r.category)).length;
  return (
    <div className="slup__rules">
      <button
        type="button"
        className="slup__rulesHead"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <Icon.ChevronRight className={"slup__rulesChev" + (open ? " slup__rulesChev--open" : "")} />
        Customize redaction rules
        <span className="slup__rulesHint">
          {onCount} of {ruleConfig.length} types on
        </span>
      </button>
      {open ? (
        <div className="slup__rulesBody">
          <p className="slup__rulesNote">
            Choose which kinds of values get redacted. High-risk types (payment cards, SSNs, emails,
            secrets) are always on.
          </p>
          <div className="slup__rulesPills" role="group" aria-label="Redaction categories">
            {ruleConfig.map((r) => {
              const meta = categoryFor(r.category);
              const on = enabledCategories.has(r.category);
              if (!r.customizable) {
                return (
                  <span
                    key={r.category}
                    className="slup__rulePill slup__rulePill--locked"
                    title={`${meta.label} — always redacted`}
                  >
                    <span className="slup__ruleDot" style={{ background: meta.color }} />
                    {meta.label}
                    <Icon.Lock />
                  </span>
                );
              }
              return (
                <button
                  key={r.category}
                  type="button"
                  className={"slup__rulePill " + (on ? "slup__rulePill--on" : "slup__rulePill--off")}
                  aria-pressed={on}
                  title={meta.desc}
                  onClick={() => toggleCategory(r.category)}
                >
                  <span
                    className="slup__ruleDot"
                    style={{ background: on ? meta.color : "transparent" }}
                  />
                  {meta.label}
                </button>
              );
            })}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function StepReview() {
  const { files, allowRuleCustomization } = useFlow();
  const counts = { text: 0, binary: 0, rejected: 0 };
  files.forEach((f) => {
    if (f.det) counts[f.det.kind]++;
  });
  return (
    <div>
      <div className="slup__detectSummary">
        <div className="slup__stat">
          <div className="slup__statNum slup__spark">{counts.text}</div>
          <div className="slup__statLabel">Text files → redacted</div>
        </div>
        <div className="slup__stat">
          <div className="slup__statNum" style={{ color: "var(--slup-accent)" }}>
            {counts.binary}
          </div>
          <div className="slup__statLabel">Images / docs → as-is</div>
        </div>
        <div className="slup__stat">
          <div className="slup__statNum" style={{ color: "var(--slup-text-muted)" }}>
            {counts.rejected}
          </div>
          <div className="slup__statLabel">Skipped (not allowed)</div>
        </div>
      </div>
      <Note icon={Icon.Info}>
        We classify each file by its bytes: a valid UTF byte-order mark or 2 KB of valid UTF-8 means{" "}
        <strong>text</strong> (gets redacted). Images and office documents on our allow-list upload
        as-is. Anything else is skipped. If something looks miscategorized, head back and remove it.
      </Note>
      {allowRuleCustomization ? <RedactRulesPanel /> : null}
      <div style={{ marginTop: 18 }}>
        <div className="slup__list">
          {files.map((f) => (
            <FileRow key={f.id} file={f} removable />
          ))}
        </div>
      </div>
    </div>
  );
}
