"use client";

import { useId } from "react";
import type { Fix } from "@/lib/scene.gen";
import { useCopy } from "@/lib/useCopy";

type LineKind = "file" | "hunk" | "add" | "del" | "ctx";

function lineKind(line: string): LineKind {
  if (line.startsWith("+++") || line.startsWith("---")) return "file";
  if (line.startsWith("@@")) return "hunk";
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "del";
  return "ctx";
}

/** A unified diff, one line per row: added lines tinted green, removed ones red. Scrolls sideways, never wraps. */
function Diff({ diff }: { diff: string }) {
  const lines = diff.split("\n");
  return (
    <pre className="fix-diff" tabIndex={0} aria-label="Suggested change">
      <code className="fix-diff-code">
        {lines.map((line, i) => (
          <span key={i} data-line={lineKind(line)}>
            {i < lines.length - 1 ? `${line}\n` : line}
          </span>
        ))}
      </code>
    </pre>
  );
}

/**
 * How to fix the selected finding: a plain explanation, the suggested change
 * as a diff, and a prompt to paste into the AI tool that built the app.
 * Parts that are empty are left out; with nothing to show it renders nothing.
 */
export function FixCard({ fix }: { fix: Fix }) {
  const { state, copy } = useCopy();
  const id = useId();
  if (!fix.explanation && !fix.diff && !fix.prompt) return null;
  return (
    <section className="fix-card" aria-labelledby={`${id}-title`}>
      <h3 id={`${id}-title`}>How to fix it</h3>
      {fix.explanation && <p className="fix-explanation">{fix.explanation}</p>}
      {fix.diff && <Diff diff={fix.diff} />}
      {fix.prompt && (
        <div className="fix-actions">
          <button type="button" className="copy-button" data-state={state} onClick={() => void copy(fix.prompt)}>
            <span aria-live="polite">{state === "copied" ? "Copied" : "Copy fix prompt"}</span>
          </button>
          {state !== "failed" && <p className="fix-hint">Paste it into the tool that built your app.</p>}
        </div>
      )}
      {fix.prompt && state === "failed" && (
        <>
          <p className="copy-failed" role="status">
            Copy failed, select the text below
          </p>
          <pre className="fix-prompt" data-testid="fix-prompt">
            {fix.prompt}
          </pre>
        </>
      )}
    </section>
  );
}
