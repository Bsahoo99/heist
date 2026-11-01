// What a shared analysis link says: the page title and the Open Graph card's words.
import { STATUS_LABEL } from "@/components/panels/FindingsList";
import { TOTAL_CHECKS } from "./badge";
import { rulesCoverage, unreadMigrationsCopy } from "./coverage";
import type { Scene } from "./scene.gen";

export const TAGLINE = "See how your vibe-coded app gets robbed, before someone else does.";

/**
 * How long the share card image may be cached. The fallback frame and the
 * tagline change once the analysis finishes or its replay is exported, so
 * they are short-lived; a real poster can be replaced by a re-export, so it
 * is cached longer but never as immutable.
 */
export const CARD_CACHE = {
  poster: "public, max-age=3600",
  fallback: "public, max-age=300",
} as const;

export function cardCacheControl(hasPoster: boolean): string {
  return hasPoster ? CARD_CACHE.poster : CARD_CACHE.fallback;
}

/**
 * `metadataBase` for absolute share URLs: NEXT_PUBLIC_SITE_URL when it is a
 * valid http(s) URL, else undefined, which leaves Next's own default (the
 * Vercel production domain on Vercel).
 */
export function siteUrl(raw: string | undefined): URL | undefined {
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    return url.protocol === "https:" || url.protocol === "http:" ? url : undefined;
  } catch {
    return undefined;
  }
}

/** `https://github.com/owner/name` -> `owner/name`; null for anything else. */
export function repoName(url: string | null | undefined): string | null {
  const m = url?.match(/^https:\/\/github\.com\/([^/]+\/[^/]+?)\/?$/);
  return m ? m[1] : null;
}

/** The page title: the repo when it is known. */
export function shareTitle(repo: string | null): string {
  return repo ? `Heist: ${repo}` : "Heist";
}

export type ShareCard = {
  headline: string;
  /** Under the headline, when there is more to say. */
  note: string | null;
};

/**
 * The card's words. A finished analysis leads with its worst finding and its
 * status ("Possible, not confirmed" for a possible one). A clean run claims
 * only the locks Heist could test, as `rulesCoverage` decides. Anything else
 * (unknown, running or failed) gets the tagline.
 */
export function shareCard(scene: Scene | null): ShareCard {
  if (!scene) return { headline: TAGLINE, note: null };
  const worst = scene.findings[0];
  if (worst) {
    const more = scene.findings.length - 1;
    const tail = more === 0 ? "" : more === 1 ? ". 1 more finding" : `. ${more} more findings`;
    return { headline: worst.title, note: `${STATUS_LABEL[worst.status]}${tail}` };
  }
  const coverage = rulesCoverage(scene);
  if (coverage === "full") {
    return {
      headline: `${scene.meta.checks_held}/${TOTAL_CHECKS} locks held`,
      note: "Heist tried every door and found no way in.",
    };
  }
  if (coverage === "partial") {
    return { headline: "No way in found", note: unreadMigrationsCopy(scene.meta.unparsed_migrations.length) };
  }
  return { headline: "No way in through the code", note: "Heist could not check the database rules." };
}
