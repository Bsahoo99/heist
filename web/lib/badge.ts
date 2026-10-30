// The README badge: its words, its colour and the SVG served at /api/badge/<id>.
import type { Scene } from "./scene.gen";

/** How many checks Heist runs. */
export const TOTAL_CHECKS = 7;

export type BadgeTone = "green" | "amber" | "red" | "grey";

const LABEL = "Heist-tested";

/**
 * The badge's words. Never claims a lock Heist did not test: without the
 * database rules (mistakes 3 and 4 need them) it says so instead of a count.
 */
export function badgeText(scene: Scene): string {
  if (!scene.meta.has_db_rules) return `${LABEL}: database rules not checked`;
  return `${LABEL}: ${scene.meta.checks_held}/${TOTAL_CHECKS} locks held`;
}

/** Green for every lock, amber for 5 or 6, red below 5, grey when the rules were not checked. */
export function badgeTone(scene: Scene): BadgeTone {
  if (!scene.meta.has_db_rules) return "grey";
  const held = scene.meta.checks_held;
  if (held >= TOTAL_CHECKS) return "green";
  if (held >= 5) return "amber";
  return "red";
}

/** Whether the page offers the badge: every check held, and the database rules were among them. */
export function offersBadge(scene: Scene): boolean {
  return scene.meta.has_db_rules && scene.meta.checks_held >= TOTAL_CHECKS;
}

/** The Markdown for a README: the badge image, linking to the analysis. */
export function badgeMarkdown(origin: string, id: string): string {
  const base = origin.replace(/\/+$/, "");
  const safe = encodeURIComponent(id);
  return `[![${LABEL}](${base}/api/badge/${safe})](${base}/a/${safe})`;
}

/** Dark enough for white text at 4.5:1 or more. */
const TONE_FILL: Record<BadgeTone, string> = {
  green: "#1f7a3a",
  amber: "#9a5800",
  red: "#b42318",
  grey: "#5c6470",
};
const LABEL_FILL = "#333a44";

const FONT_SIZE = 11;
const PAD = 7;
const HEIGHT = 20;

/** Rough advance widths (px) at 11px Verdana, the usual badge face. */
function textWidth(text: string): number {
  let w = 0;
  for (const ch of text) {
    if ("il.:,;'|!".includes(ch)) w += 3.4;
    else if ("ftjr/()- ".includes(ch)) w += 4.4;
    else if ("mwMW".includes(ch)) w += 10.4;
    else if (/[A-Z]/.test(ch)) w += 7.6;
    else if (/[0-9]/.test(ch)) w += 7;
    else w += 6.6;
  }
  return Math.ceil(w);
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * A flat two-part badge in the shields.io style: the label on the left, the
 * rest of `text` (after the first ": ") on the right. The full text is the
 * SVG's title and accessible name.
 */
export function badgeSvg(text: string, tone: BadgeTone): string {
  const cut = text.indexOf(": ");
  const left = cut >= 0 ? text.slice(0, cut) : LABEL;
  const right = cut >= 0 ? text.slice(cut + 2) : text;
  const lw = textWidth(left) + PAD * 2;
  const rw = textWidth(right) + PAD * 2;
  const width = lw + rw;
  const all = escapeXml(text);
  const ty = 14;
  const label = (s: string, x: number) =>
    `<text x="${x}" y="${ty + 1}" fill="#010101" fill-opacity=".3">${escapeXml(s)}</text>` +
    `<text x="${x}" y="${ty}">${escapeXml(s)}</text>`;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${HEIGHT}" viewBox="0 0 ${width} ${HEIGHT}" role="img" aria-label="${all}">` +
    `<title>${all}</title>` +
    `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>` +
    `<clipPath id="r"><rect width="${width}" height="${HEIGHT}" rx="3" fill="#fff"/></clipPath>` +
    `<g clip-path="url(#r)">` +
    `<rect width="${lw}" height="${HEIGHT}" fill="${LABEL_FILL}"/>` +
    `<rect x="${lw}" width="${rw}" height="${HEIGHT}" fill="${TONE_FILL[tone]}"/>` +
    `<rect width="${width}" height="${HEIGHT}" fill="url(#s)"/>` +
    `</g>` +
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="${FONT_SIZE}">` +
    label(left, lw / 2) +
    label(right, lw + rw / 2) +
    `</g>` +
    `</svg>`
  );
}
