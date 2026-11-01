"use client";

import { useEffect, useId, useState } from "react";
import { getExports, type Exports } from "@/lib/api";

/** The exported replay's links for an analysis, asked of the engine once. Null until known, or without an id. */
export function useExports(id: string | undefined): Exports | null {
  const [exports, setExports] = useState<{ id: string; links: Exports } | null>(null);
  useEffect(() => {
    if (!id) return;
    let active = true;
    // Downloads are extras: any failure just leaves them out.
    getExports(id).then(
      (links) => {
        if (active) setExports({ id, links });
      },
      () => {},
    );
    return () => {
      active = false;
    };
  }, [id]);
  return exports && exports.id === id ? exports.links : null;
}

/** "Download MP4" and "Download GIF" for an exported replay; nothing when neither file exists. */
export function ExportLinks({ exports }: { exports: Exports | null }) {
  const headingId = useId();
  if (!exports?.mp4 && !exports?.gif) return null;
  return (
    <section className="export-links" aria-labelledby={headingId}>
      <h2 id={headingId}>Share the replay</h2>
      <div className="export-actions">
        {exports.mp4 && (
          <a className="export-link" href={exports.mp4} download>
            Download MP4
          </a>
        )}
        {exports.gif && (
          <a className="export-link" href={exports.gif} download>
            Download GIF
          </a>
        )}
      </div>
    </section>
  );
}
