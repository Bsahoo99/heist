// The pure half of `pnpm export` (scripts/export-replay.ts): arguments, the
// recording URL, trim maths, ffmpeg argument lists and the Storage upload
// request. No I/O here, so it is tested with vitest. Node runs it as is
// (type stripping), so it keeps to erasable syntax and relative `.ts` imports.
import { parseArgs } from "node:util";
import { isAnalysisId } from "../lib/analysisId.ts";

export const USAGE = "Usage: pnpm export --id <id> [--base <url>] [--engine <url>] [--no-upload]";
export const DEFAULT_BASE = "http://localhost:3000";
/** Same default as the web app's engine client (lib/api.ts). */
export const DEFAULT_ENGINE = "http://127.0.0.1:8000";

export const VIEWPORT = { width: 1280, height: 720 };
export const FPS = 30;
export const GIF_WIDTH = 720;
export const GIF_FPS = 12;
/** How long to wait for the page to start, and then for the replay to finish. */
export const WAIT_MS = 60_000;
/** Footage kept after the page says it is done, so the end card does not cut off. */
export const TAIL_MS = 1_000;

export const EXPORTS_BUCKET = "exports";
export type ExportKind = "mp4" | "gif" | "png";
export const EXPORT_KINDS: ExportKind[] = ["mp4", "gif", "png"];
export const MIME: Record<ExportKind, string> = { mp4: "video/mp4", gif: "image/gif", png: "image/png" };

export type ExportOptions = { id: string; base: string; engine: string; upload: boolean };

type Env = Record<string, string | undefined>;

function httpBase(name: string, raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${name} must be an http(s) URL.`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`${name} must be an http(s) URL.`);
  return raw.replace(/\/+$/, "");
}

/**
 * `--id` (required, an engine id), `--base` (the web app, default
 * localhost:3000), `--engine` (else HEIST_ENGINE_URL, then
 * NEXT_PUBLIC_ENGINE_URL, then the local engine) and `--no-upload`.
 * Throws an Error with plain words on anything else.
 */
export function parseExportArgs(argv: string[], env: Env): ExportOptions {
  const args = argv[0] === "--" ? argv.slice(1) : argv;
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      base: { type: "string" },
      engine: { type: "string" },
      "no-upload": { type: "boolean" },
    },
    strict: true,
    allowPositionals: false,
  });
  const id = values.id ?? "";
  if (!isAnalysisId(id)) throw new Error("--id must be an analysis id (letters, digits, - and _, up to 64).");
  const engine = values.engine || env.HEIST_ENGINE_URL || env.NEXT_PUBLIC_ENGINE_URL || DEFAULT_ENGINE;
  return {
    id,
    base: httpBase("--base", values.base || DEFAULT_BASE),
    engine: httpBase("--engine", engine),
    upload: !values["no-upload"],
  };
}

/** The page `pnpm export` films. */
export function recordUrl(base: string, id: string): string {
  return `${base}/a/${encodeURIComponent(id)}?record=1`;
}

/** Seconds of page loading to cut from the start of the video, which starts with the page. */
export function trimSeconds(videoStartMs: number, startedAtMs: number): number {
  return Math.max(0, Math.round(startedAtMs - videoStartMs)) / 1000;
}

/** The recording, trimmed to the replay's first frame, as H.264 MP4 at 30 fps that starts playing at once. */
export function mp4Args(webm: string, trim: number, out: string): string[] {
  return [
    "-y",
    "-loglevel",
    "error",
    "-ss",
    trim.toFixed(3),
    "-i",
    webm,
    "-an",
    "-c:v",
    "libx264",
    "-preset",
    "slow",
    "-crf",
    "18",
    "-pix_fmt",
    "yuv420p",
    "-r",
    String(FPS),
    "-movflags",
    "+faststart",
    out,
  ];
}

const GIF_SCALE = `fps=${GIF_FPS},scale=${GIF_WIDTH}:-1:flags=lanczos`;

/** First GIF pass: one palette for the whole clip. */
export function paletteArgs(mp4: string, palette: string): string[] {
  return ["-y", "-loglevel", "error", "-i", mp4, "-vf", `${GIF_SCALE},palettegen=stats_mode=diff`, palette];
}

/** Second GIF pass: 720 px wide at 12 fps with that palette. */
export function gifArgs(mp4: string, palette: string, out: string): string[] {
  return [
    "-y",
    "-loglevel",
    "error",
    "-i",
    mp4,
    "-i",
    palette,
    "-lavfi",
    `${GIF_SCALE}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle`,
    out,
  ];
}

export type SupabaseTarget = { url: string; key: string };

/** The only two names an upload reads, from the environment or engine/.env. */
export const SUPABASE_URL_NAME = "SUPABASE_URL";
export const SUPABASE_KEY_NAME = "SUPABASE_SERVICE_ROLE_KEY";

/**
 * Heist's Supabase URL and service role key: from the environment, else from
 * engine/.env (`file`, already parsed). Only these two names are read.
 */
export function supabaseTarget(env: Env, file: Env): SupabaseTarget {
  const url = env[SUPABASE_URL_NAME] || file[SUPABASE_URL_NAME] || "";
  const key = env[SUPABASE_KEY_NAME] || file[SUPABASE_KEY_NAME] || "";
  if (!url || !key) {
    const names = `${SUPABASE_URL_NAME} and ${SUPABASE_KEY_NAME}`;
    throw new Error(`Uploading needs ${names} (in the environment or engine/.env). Pass --no-upload to skip it.`);
  }
  return { url: httpBase(SUPABASE_URL_NAME, url), key };
}

/**
 * One file's upload to the private `exports` bucket, replacing any earlier
 * export. The key goes in headers only, as the engine sends it
 * (heist/store.py): an `sb_secret_` key in `apikey` alone, a legacy JWT also
 * as the bearer token.
 */
export function uploadRequest(
  target: SupabaseTarget,
  id: string,
  kind: ExportKind,
): { url: string; headers: Record<string, string> } {
  const headers: Record<string, string> = {
    apikey: target.key,
    "Content-Type": MIME[kind],
    "x-upsert": "true",
  };
  if (target.key.startsWith("eyJ")) headers.Authorization = `Bearer ${target.key}`;
  return { url: `${target.url}/storage/v1/object/${EXPORTS_BUCKET}/${id}.${kind}`, headers };
}
