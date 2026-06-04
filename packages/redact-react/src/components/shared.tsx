import type { ReactNode } from "react";
import * as Icon from "../icons.tsx";
import { fmtBytes } from "../util.ts";
import { useFlow, type WizardFile } from "../flow.tsx";

export function Note({
  variant,
  icon: IconComp = Icon.Info,
  role,
  children,
}: {
  variant?: "warn" | "bad";
  icon?: (p: any) => ReactNode;
  role?: string;
  children: ReactNode;
}) {
  const cls = "slup__note" + (variant ? " slup__note--" + variant : "");
  return (
    <div className={cls} role={role}>
      <IconComp aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

function TypeBadge({ det }: { det: WizardFile["det"] }) {
  const { showTip, hideTip, policy } = useFlow();
  if (!det) return <span className="slup__badge slup__badge--rejected">…</span>;
  if (det.kind === "text")
    return <span className="slup__badge slup__badge--text">{"Text · " + det.encoding}</span>;
  if (det.kind === "binary")
    return (
      <span className="slup__badge slup__badge--binary">
        {(policy.imageExtensions.has(det.ext) ? "Image" : "Doc") + " · ." + det.ext}
      </span>
    );
  const meta =
    "Only properly encoded text files, office documents, and images are accepted. Other files are ignored and will not be uploaded.";
  return (
    <span
      className="slup__badge slup__badge--rejected"
      tabIndex={0}
      aria-label={"Skipped. " + meta}
      onMouseEnter={(e) => showTip(e, "Skipped", "var(--slup-text-muted)", meta)}
      onMouseLeave={hideTip}
      onFocus={(e) => showTip(e, "Skipped", "var(--slup-text-muted)", meta)}
      onBlur={hideTip}
    >
      Skipped
    </span>
  );
}

function RowIcon({ det }: { det: WizardFile["det"] }) {
  const { policy } = useFlow();
  let Comp = Icon.FileQuestion;
  if (det) {
    if (det.kind === "text") Comp = Icon.FileText;
    else if (det.kind === "binary") Comp = policy.imageExtensions.has(det.ext) ? Icon.Image : Icon.File;
  }
  return (
    <span className="slup__rowIcon">
      <Comp />
    </span>
  );
}

function NoRedactTag({ det }: { det: WizardFile["det"] }) {
  const { showTip, hideTip } = useFlow();
  if (!det || det.kind !== "binary") return null;
  const meta =
    (det.isImage ? "Images" : "Office documents") +
    " upload exactly as-is. Redaction only runs on text. Open it in the preview step and check for personal data before sending.";
  return (
    <span
      className="slup__tag"
      tabIndex={0}
      role="img"
      aria-label={"Not redacted. " + meta}
      onMouseEnter={(e) => showTip(e, "Not redacted", "var(--slup-warn)", meta)}
      onMouseLeave={hideTip}
      onFocus={(e) => showTip(e, "Not redacted", "var(--slup-warn)", meta)}
      onBlur={hideTip}
    >
      <Icon.ShieldOff />
    </span>
  );
}

export function FileRow({ file, removable }: { file: WizardFile; removable: boolean }) {
  const { removeFile } = useFlow();
  const dir = file.path.includes("/") ? file.path.slice(0, file.path.lastIndexOf("/")) : "";
  const rejected = file.det && file.det.kind === "rejected";
  return (
    <div className={"slup__row" + (rejected ? " slup__row--rejected" : "")}>
      <RowIcon det={file.det} />
      <div className="slup__rowMain">
        <div className="slup__rowName" title={file.name}>
          {file.name}
        </div>
        {dir ? (
          <div className="slup__rowPath" title={dir}>
            {dir + "/"}
          </div>
        ) : null}
      </div>
      <span className="slup__rowSize">{fmtBytes(file.size)}</span>
      <span className="slup__badgeCell">
        <TypeBadge det={file.det} />
        <NoRedactTag det={file.det} />
      </span>
      {removable ? (
        <button
          className="slup__rowX"
          onClick={() => removeFile(file.id)}
          title="Remove"
          aria-label={"Remove " + file.name}
        >
          <Icon.X />
        </button>
      ) : (
        <span />
      )}
    </div>
  );
}

export function FloatingTip() {
  const { tip } = useFlow();
  if (!tip) return null;
  const above = tip.top > 150;
  return (
    <div
      className="slup__floatTip"
      role="tooltip"
      aria-hidden="true"
      style={{
        left: tip.left + "px",
        top: (above ? tip.top - 10 : tip.bottom + 10) + "px",
        transform: above ? "translate(-50%, -100%)" : "translate(-50%, 0)",
      }}
    >
      <span className="slup__tipKey" style={{ color: tip.color }}>
        {tip.label}
      </span>
      <span className="slup__tipMeta">{tip.meta}</span>
    </div>
  );
}
