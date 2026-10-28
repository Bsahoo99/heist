"use client";

import { useId, useRef, useState, type KeyboardEvent } from "react";
import type { CodeRef, PathStep } from "@/lib/scene.gen";

const TABS = ["Story", "Why", "Code"] as const;
type Tab = (typeof TABS)[number];

/** `file:start-end` (or `file:line` for one line). */
export function refLabel(ref: CodeRef): string {
  return ref.start_line === ref.end_line
    ? `${ref.file}:${ref.start_line}`
    : `${ref.file}:${ref.start_line}-${ref.end_line}`;
}

/**
 * One stop of a route, in three tabs: Story (the heist metaphor), Why and
 * Code (plain and technical). Everything is rendered as plain text.
 */
export function StepPanel({ step, heading }: { step: PathStep; heading?: string }) {
  const [tab, setTab] = useState<Tab>("Story");
  const id = useId();
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  const onKey = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    let next = -1;
    if (e.key === "ArrowRight") next = (i + 1) % TABS.length;
    else if (e.key === "ArrowLeft") next = (i - 1 + TABS.length) % TABS.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = TABS.length - 1;
    if (next < 0) return;
    e.preventDefault();
    e.stopPropagation();
    setTab(TABS[next]);
    refs.current[next]?.focus();
  };

  return (
    <section className="step-panel" aria-label={heading ?? "This stop"}>
      {heading && <h3 className="step-panel-heading">{heading}</h3>}
      <div role="tablist" aria-label="Explain this stop" className="step-panel-tabs">
        {TABS.map((t, i) => (
          <button
            key={t}
            ref={(el) => {
              refs.current[i] = el;
            }}
            id={`${id}-tab-${t}`}
            type="button"
            role="tab"
            aria-selected={tab === t}
            aria-controls={`${id}-panel`}
            tabIndex={tab === t ? 0 : -1}
            onClick={() => setTab(t)}
            onKeyDown={(e) => onKey(e, i)}
            className="step-panel-tab"
          >
            {t}
          </button>
        ))}
      </div>
      <div
        id={`${id}-panel`}
        role="tabpanel"
        aria-labelledby={`${id}-tab-${tab}`}
        tabIndex={0}
        className="step-panel-body"
      >
        {tab === "Story" && <p className="step-panel-story">{step.story}</p>}
        {tab === "Why" && <p className="step-panel-text">{step.why}</p>}
        {tab === "Code" && (
          <div className="step-panel-code">
            {step.ref && <p className="step-panel-ref">{refLabel(step.ref)}</p>}
            <pre>{step.code}</pre>
            {step.data && (
              <dl className="step-panel-data">
                <dt>Data at this stop</dt>
                <dd>{step.data}</dd>
              </dl>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
