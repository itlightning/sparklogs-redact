import { useRef } from "react";
import * as Icon from "../icons.tsx";
import { fmtBytes } from "../util.ts";
import { useFlow } from "../flow.tsx";
import { FileRow, Note } from "./shared.tsx";

export function StepSelect() {
  const flow = useFlow();
  const { files, uploadable, totalSize, overLimit, dragOver, policy } = flow;
  const fileInput = useRef<HTMLInputElement>(null);
  const dirInput = useRef<HTMLInputElement>(null);

  const pct = Math.min(100, (totalSize / policy.maxTotalBytes) * 100);
  const meterMod =
    totalSize > policy.maxTotalBytes
      ? " slup__meterFill--over"
      : pct > 80
        ? " slup__meterFill--warn"
        : "";

  return (
    <div>
      <div
        className={"slup__drop" + (dragOver ? " slup__drop--over" : "")}
        onDragOver={(e) => {
          e.preventDefault();
          flow.setDragOver(true);
        }}
        onDragLeave={() => flow.setDragOver(false)}
        onDrop={flow.onDrop}
      >
        <div className="slup__dropIcon">
          <Icon.UploadCloud />
        </div>
        <div className="slup__dropTitle">Drag folders or files here</div>
        <div className="slup__dropSub">
          Everything is processed in your browser. Nothing is sent until you confirm.
        </div>
        <div className="slup__dropBtns">
          <button className="slup__btn slup__btn--ghost" onClick={() => fileInput.current?.click()}>
            <Icon.FilePlus />
            Choose files
          </button>
          <button className="slup__btn slup__btn--ghost" onClick={() => dirInput.current?.click()}>
            <Icon.Folder />
            Choose a folder
          </button>
        </div>
        <input
          ref={fileInput}
          type="file"
          multiple
          onChange={flow.onPick}
          style={{ display: "none" }}
        />
        <input
          ref={dirInput}
          type="file"
          /* @ts-expect-error non-standard directory attributes */
          webkitdirectory=""
          directory=""
          multiple
          onChange={flow.onPick}
          style={{ display: "none" }}
        />
      </div>

      {files.length ? (
        <div className="slup__meter">
          <div className="slup__meterTop">
            <span className="slup__meterLabel">
              {files.length + " file" + (files.length > 1 ? "s" : "") + " · " + uploadable.length + " will upload"}
            </span>
            <span className="slup__meterVal">
              {fmtBytes(totalSize) + " / " + fmtBytes(policy.maxTotalBytes)}
            </span>
          </div>
          <div className="slup__meterTrack">
            <div
              className={"slup__meterFill" + meterMod}
              style={{ width: Math.min(100, pct) + "%" }}
            />
          </div>
        </div>
      ) : null}

      {overLimit ? (
        <Note variant="warn" icon={Icon.Alert}>
          {totalSize > policy.maxTotalBytes
            ? "Over the " + fmtBytes(policy.maxTotalBytes) + " limit. Remove some files to continue."
            : "Too many files (max " + policy.maxFiles + ")."}
        </Note>
      ) : null}

      {files.length ? (
        <div style={{ marginTop: 18 }}>
          <div className="slup__listHead">
            <span className="slup__listTitle">Added</span>
            <button className="slup__btn slup__btn--quiet" onClick={flow.clearAll}>
              <Icon.Trash />
              Clear all
            </button>
          </div>
          <div className="slup__list">
            {files.map((f) => (
              <FileRow key={f.id} file={f} removable />
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
