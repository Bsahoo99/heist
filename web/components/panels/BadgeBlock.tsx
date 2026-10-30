"use client";

import { useId, useSyncExternalStore } from "react";
import type { Scene } from "@/lib/scene.gen";
import { badgeMarkdown, badgeText } from "@/lib/badge";
import { useCopy } from "@/lib/useCopy";

const noSubscribe = () => () => {};

/** This site's origin in the browser; empty on the server. */
function useOrigin(): string {
  return useSyncExternalStore(
    noSubscribe,
    () => window.location.origin,
    () => "",
  );
}

/** The README badge for an analysis: how it looks, its Markdown, and a copy button. */
export function BadgeBlock({ scene, id }: { scene: Scene; id: string }) {
  const origin = useOrigin();
  const { state, copy } = useCopy();
  const headingId = useId();
  const markdown = badgeMarkdown(origin, id);
  return (
    <section className="badge-block" aria-labelledby={`${headingId}-title`}>
      <h2 id={`${headingId}-title`}>Add the badge to your README</h2>
      {/* An SVG from our own route; next/image would need SVG support switched on for this one image. */}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img className="badge-image" src={`/api/badge/${encodeURIComponent(id)}`} alt={badgeText(scene)} height={20} />
      <pre className="badge-markdown" tabIndex={0} aria-label="Badge Markdown">
        <code data-testid="badge-markdown">{markdown}</code>
      </pre>
      <div className="badge-actions">
        <button type="button" className="copy-button" data-state={state} onClick={() => void copy(markdown)}>
          <span aria-live="polite">{state === "copied" ? "Copied" : "Copy badge"}</span>
        </button>
        {state === "failed" && (
          <p className="copy-failed" role="status">
            Copy failed, select the text above
          </p>
        )}
      </div>
    </section>
  );
}
