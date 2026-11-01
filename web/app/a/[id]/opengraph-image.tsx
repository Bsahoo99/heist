import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ImageResponse } from "next/og";
import { isAnalysisId } from "@/lib/analysisId";
import { getAnalysis, getExports, serverEngineUrl, type Analysis } from "@/lib/api";
import type { Scene } from "@/lib/scene.gen";
import { repoName, shareCard } from "@/lib/share";

export const alt = "A Heist replay of the app's map, with its top finding";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

/** Give up on the engine and the poster after this long: a slow engine never holds a link preview. */
const FETCH_TIMEOUT_MS = 4_000;
/** Posters are 1280x720 PNGs of a few hundred KB; anything far bigger is not one. */
const MAX_POSTER_BYTES = 8 * 1024 * 1024;

// A real record-mode frame of the map (the vulnerable fixture at its start),
// for analyses without an exported poster. Read once, as the docs advise.
const FALLBACK = `data:image/png;base64,${await readFile(join(process.cwd(), "public/og/city.png"), "base64")}`;

const COLORS = { bg: "#0b1220", ink: "#e6edf7", muted: "#9fb0c8", lamp: "#f2c46d" };

/** The exported poster frame as a data URI, or null when there is none or it cannot be fetched. */
async function posterFor(id: string, base: string): Promise<string | null> {
  const { png } = await getExports(id, { base, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!png) return null;
  try {
    const res = await fetch(png, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), cache: "no-store" });
    if (!res.ok || res.headers.get("content-type") !== "image/png") return null;
    const bytes = Buffer.from(await res.arrayBuffer());
    if (bytes.length === 0 || bytes.length > MAX_POSTER_BYTES) return null;
    return `data:image/png;base64,${bytes.toString("base64")}`;
  } catch {
    return null;
  }
}

/**
 * The link preview of a shared analysis: the replay's poster frame (or a fixed
 * map frame) under the repo and its top finding, or the clean verdict. Unknown
 * and unfinished analyses get the fixed frame and the tagline. Fetch failures
 * fall back, never break the image.
 */
export default async function Image({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let analysis: Analysis | null = null;
  let poster: string | null = null;
  if (isAnalysisId(id)) {
    const base = serverEngineUrl();
    analysis = await getAnalysis(id, { base, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) }).catch(() => null);
    if (analysis?.status === "done") poster = await posterFor(id, base);
  }
  const scene: Scene | null = analysis?.status === "done" ? analysis.scene : null;
  const card = shareCard(scene);
  const repo = repoName(analysis?.url);

  return new ImageResponse(
    (
      <div style={{ display: "flex", position: "relative", width: "100%", height: "100%", background: COLORS.bg }}>
        {/* The frame is 1280x720: scaled to the card's width, its caption strip falls under the words. */}
        <img src={poster ?? FALLBACK} alt="" width={1200} height={675} style={{ position: "absolute", top: 0, left: 0 }} />
        <div
          style={{
            position: "absolute",
            left: 0,
            right: 0,
            bottom: 0,
            height: 300,
            display: "flex",
            flexDirection: "column",
            justifyContent: "flex-end",
            padding: "0 56px 44px",
            backgroundImage: `linear-gradient(to bottom, rgba(11, 18, 32, 0), rgba(11, 18, 32, 0.94) 42%, ${COLORS.bg})`,
          }}
        >
          <div style={{ display: "flex", alignItems: "baseline", gap: 18, fontSize: 26 }}>
            <span style={{ color: COLORS.lamp, fontWeight: 700, letterSpacing: 3 }}>HEIST</span>
            {repo && <span style={{ color: COLORS.muted }}>{repo}</span>}
          </div>
          <div
            style={{
              display: "flex",
              marginTop: 10,
              fontSize: 54,
              fontWeight: 700,
              lineHeight: 1.12,
              color: COLORS.ink,
              maxWidth: 1088,
            }}
          >
            {card.headline}
          </div>
          {card.note && (
            <div style={{ display: "flex", marginTop: 12, fontSize: 28, color: COLORS.muted }}>{card.note}</div>
          )}
        </div>
      </div>
    ),
    { ...size },
  );
}
