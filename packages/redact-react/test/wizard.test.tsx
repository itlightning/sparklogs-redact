import type { ReactNode } from "react";
import { test, expect } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { userEvent } from "@testing-library/user-event";
import { RedactUploadWizard } from "../src/RedactUploadWizard.tsx";
import type { ConsentItem, PreviewRenderArgs } from "../src/types.ts";

const consents: ConsentItem[] = [
  {
    id: "support",
    label: "Technical support",
    desc: "Diagnose my issue.",
    required: true,
    group: "primary",
  },
  { id: "product", label: "Improve the product", desc: "Retain to improve.", group: "optional" },
];

// A deterministic stand-in for the default (lazy CodeMirror) preview. Exercising the public
// `renderPreview` contract keeps this flow test independent of CM6's DOM/layout behavior (which does
// not virtualize meaningfully under happy-dom) while still asserting on real redact-core output:
// the replacement pills are sliced straight from `outStart`/`outEnd`.
function testPreview(args: PreviewRenderArgs): ReactNode {
  const { text, redactions, categoryFor } = args;
  if (!redactions?.length) return <pre className="test-preview">{text}</pre>;
  const sorted = [...redactions].sort((a, b) => a.outStart - b.outStart);
  const parts: ReactNode[] = [];
  let cursor = 0;
  sorted.forEach((r, i) => {
    if (r.outStart >= r.outEnd) return;
    if (r.outStart > cursor) parts.push(text.slice(cursor, r.outStart));
    const meta = categoryFor?.(r.category);
    parts.push(
      <span
        key={i}
        className="test-pill"
        aria-label={`${meta?.label ?? r.category} redaction`}
      >
        {text.slice(r.outStart, r.outEnd)}
      </span>,
    );
    cursor = r.outEnd;
  });
  if (cursor < text.length) parts.push(text.slice(cursor));
  return <pre className="test-preview">{parts}</pre>;
}

function renderWizard() {
  return render(
    <RedactUploadWizard
      consents={consents}
      onSubmit={async () => ({ referenceId: "REF123" })}
      copy={{ railTitle: "Upload logs" }}
      renderPreview={testPreview}
    />,
  );
}

test("renders the first step with the configured rail title and file controls", () => {
  renderWizard();
  expect(screen.getByRole("heading", { name: /add your log files/i })).toBeInTheDocument();
  expect(screen.getByText("Upload logs")).toBeInTheDocument(); // copy.railTitle
  expect(screen.getByRole("button", { name: /choose files/i })).toBeInTheDocument();
});

test("redacts a selected log file and exposes accessible form labels at the details step", async () => {
  const user = userEvent.setup();
  const { container } = renderWizard();

  // Add a text file containing PII via the (hidden) file input.
  const fileInput = container.querySelector('input[type="file"]') as HTMLInputElement;
  const file = new File(["user \\Users\\alice from 10.0.0.5\n"], "cbs.log", { type: "text/plain" });
  Object.defineProperty(fileInput, "files", { value: [file], configurable: true });
  fireEvent.change(fileInput);

  // Classification is async; the row appears and "Continue" enables.
  await screen.findByText("cbs.log");
  const next = () => container.querySelector(".slup__btn--primary") as HTMLButtonElement;
  await waitFor(() => expect(next()).not.toBeDisabled());

  await user.click(next()); // step 0 -> 1 (review)
  await waitFor(() => expect(next()).not.toBeDisabled());
  await user.click(next()); // step 1 -> 2 (redact) — triggers the redaction pass

  // A redaction highlight pill (the username fake) appears via the host renderPreview.
  const pill = await waitFor(
    () => {
      const p = container.querySelector(".test-pill");
      expect(p).toBeTruthy();
      return p as HTMLElement;
    },
    { timeout: 4000 },
  );
  expect(pill.textContent).toMatch(/^User\d+$/);
  // The redacted preview must NOT contain the raw original token.
  expect(container.querySelector(".test-preview")?.textContent).not.toContain("alice");
  // The pill carries an accessible label (not a bare visual tooltip).
  expect(pill).toHaveAttribute("aria-label", expect.stringMatching(/redaction/i));

  await waitFor(() => expect(next()).not.toBeDisabled());
  await user.click(next()); // step 2 -> 3 (details)

  // A11y: labels are programmatically associated with their inputs. (exact:false because the required
  // fields' visible label carries a decorative "*"; it is aria-hidden, so the accessible name is clean.)
  expect(screen.getByLabelText("Email", { exact: false })).toBeInstanceOf(HTMLInputElement);
  expect(screen.getByLabelText("Name", { exact: false })).toBeInstanceOf(HTMLInputElement);
  // The host-defined consent is rendered.
  expect(screen.getByText("Technical support")).toBeInTheDocument();
});
