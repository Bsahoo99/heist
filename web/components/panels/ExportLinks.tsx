"use client";

import { useCallback, useEffect, useId, useState, type MouseEvent } from "react";
import { getExports, type Exports } from "@/lib/api";
import { openUrl } from "@/lib/openUrl";

/** The engine signs links for an hour; older than this, a click asks for fresh ones first. */
export const LINK_MAX_AGE_MS = 50 * 60 * 1000;

type Fetched = { id: string; links: Exports; at: number };

export type ExportsState = {
  /** The exported replay's links; null until known, or without an id. */
  links: Exports | null;
  /** The link for `kind`, signed again first when the current one is close to expiring. */
  freshLink: (kind: "mp4" | "gif") => Promise<string | null>;
  /** Whether the links are old enough that a click should ask for fresh ones. */
  isStale: () => boolean;
};

/** The exported replay's links for an analysis, asked of the engine once and again only when they get old. */
export function useExports(id: string | undefined): ExportsState {
  const [fetched, setFetched] = useState<Fetched | null>(null);
  useEffect(() => {
    if (!id) return;
    let active = true;
    // Downloads are extras: any failure just leaves them out.
    getExports(id).then(
      (links) => {
        if (active) setFetched({ id, links, at: Date.now() });
      },
      () => {},
    );
    return () => {
      active = false;
    };
  }, [id]);
  const current = fetched && fetched.id === id ? fetched : null;
  const isStale = useCallback(() => !current || Date.now() - current.at > LINK_MAX_AGE_MS, [current]);
  const freshLink = useCallback(
    async (kind: "mp4" | "gif") => {
      if (!id) return null;
      if (current && !isStale()) return current.links[kind];
      const links = await getExports(id).catch(() => null);
      if (!links) return null;
      setFetched({ id, links, at: Date.now() });
      return links[kind];
    },
    [id, current, isStale],
  );
  return { links: current?.links ?? null, freshLink, isStale };
}

/** "Download MP4" and "Download GIF" for an exported replay; nothing when neither file exists. */
export function ExportLinks({ exports }: { exports: ExportsState }) {
  const headingId = useId();
  const { links, freshLink, isStale } = exports;
  if (!links?.mp4 && !links?.gif) return null;

  // A tab left open past the links' hour would offer a dead download: sign again on click.
  const onClick = (kind: "mp4" | "gif") => (e: MouseEvent<HTMLAnchorElement>) => {
    if (!isStale()) return;
    e.preventDefault();
    void freshLink(kind).then((url) => {
      if (url) openUrl(url);
    });
  };

  return (
    <section className="export-links" aria-labelledby={headingId}>
      <h2 id={headingId}>Share the replay</h2>
      <div className="export-actions">
        {links.mp4 && (
          <a className="export-link" href={links.mp4} download onClick={onClick("mp4")}>
            Download MP4
          </a>
        )}
        {links.gif && (
          <a className="export-link" href={links.gif} download onClick={onClick("gif")}>
            Download GIF
          </a>
        )}
      </div>
    </section>
  );
}
