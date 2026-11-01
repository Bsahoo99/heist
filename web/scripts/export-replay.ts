// `pnpm export --id <id> [--base <url>] [--engine <url>] [--no-upload]`
//
// Films a finished analysis's replay in record mode (`/a/<id>?record=1`) and
// writes web/exports/<id>.mp4 (H.264, 30 fps), <id>.gif (720 px, 12 fps) and
// <id>.png (a 1280x720 poster at the replay's peak). Unless --no-upload, it
// uploads all three to Heist's private Storage bucket `exports`, from which the
// engine hands out signed links. Needs the web app running at --base, the
// engine that has the analysis, Playwright's Chromium and ffmpeg.
//
// Node runs this file directly (type stripping): erasable TypeScript only.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseEnv } from "node:util";
import { chromium, type Browser, type Page } from "playwright";
import {
  EXPORT_KINDS,
  SUPABASE_KEY_NAME,
  SUPABASE_URL_NAME,
  TAIL_MS,
  USAGE,
  VIEWPORT,
  WAIT_MS,
  gifArgs,
  mp4Args,
  paletteArgs,
  parseExportArgs,
  recordUrl,
  supabaseTarget,
  trimSeconds,
  uploadRequest,
  type ExportOptions,
  type SupabaseTarget,
} from "./export-plan.ts";

const WEB_DIR = resolve(import.meta.dirname, "..");
const OUT_DIR = join(WEB_DIR, "exports");
const ENGINE_ENV = resolve(WEB_DIR, "../engine/.env");
const ENGINE_TIMEOUT_MS = 10_000;

/** A failure with plain words for the terminal; never a key or a response body. */
class ExportError extends Error {}

function ffmpeg(args: string[], step: string): void {
  const run = spawnSync("ffmpeg", args, { stdio: ["ignore", "inherit", "inherit"] });
  if (run.error) throw new ExportError(`ffmpeg could not run (${step}): ${run.error.message}`);
  if (run.status !== 0) throw new ExportError(`ffmpeg failed (${step}), exit ${run.status}.`);
}

function checkFfmpeg(): void {
  const run = spawnSync("ffmpeg", ["-version"], { stdio: "ignore" });
  if (run.error || run.status !== 0) throw new ExportError("Install ffmpeg first: brew install ffmpeg");
}

/** Heist's Supabase from the environment, else only its two names from engine/.env. */
function readSupabaseTarget(): SupabaseTarget {
  const file = existsSync(ENGINE_ENV) ? parseEnv(readFileSync(ENGINE_ENV, "utf8")) : {};
  return supabaseTarget(process.env, {
    [SUPABASE_URL_NAME]: file[SUPABASE_URL_NAME],
    [SUPABASE_KEY_NAME]: file[SUPABASE_KEY_NAME],
  });
}

/** Only a finished analysis has a replay to film. */
async function checkDone(opts: ExportOptions): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${opts.engine}/analyses/${opts.id}`, { signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS) });
  } catch {
    throw new ExportError(`Could not reach the engine at ${opts.engine}. Pass --engine or set HEIST_ENGINE_URL.`);
  }
  if (res.status === 404) throw new ExportError(`The engine at ${opts.engine} has no analysis ${opts.id}.`);
  if (!res.ok) throw new ExportError(`The engine answered HTTP ${res.status} for analysis ${opts.id}.`);
  const body = (await res.json().catch(() => null)) as { status?: unknown } | null;
  if (body?.status !== "done") {
    const status = typeof body?.status === "string" ? body.status : "unknown";
    throw new ExportError(`Analysis ${opts.id} is ${status}, not done. Only a finished analysis can be exported.`);
  }
}

/** Waits for a body flag; record mode's `done="failed"` (an unknown or failed analysis) stops at once. */
async function waitForFlag(page: Page, flag: "started" | "climax" | "done"): Promise<void> {
  try {
    await page.waitForFunction(
      (name) => {
        const flags = document.body.dataset;
        return flags.done === "failed" || flags[name] === "true";
      },
      flag,
      { polling: "raf", timeout: WAIT_MS },
    );
  } catch {
    throw new ExportError(`The page never set data-${flag} within ${WAIT_MS / 1000} s. Is the web app at --base running?`);
  }
  const failed = await page.evaluate(() => document.body.dataset.done === "failed");
  if (failed) throw new ExportError("The page could not load this analysis (data-done=failed).");
}

/** Films the replay; returns the WebM and how many seconds of page loading lead it. */
async function film(browser: Browser, url: string, dir: string): Promise<{ webm: string; trim: number }> {
  const context = await browser.newContext({
    viewport: VIEWPORT,
    deviceScaleFactor: 1,
    recordVideo: { dir, size: VIEWPORT },
  });
  // The video starts with the page.
  const videoStart = Date.now();
  const page = await context.newPage();
  try {
    await page.goto(url);
    await waitForFlag(page, "started");
    const startedAt = Date.now();
    await waitForFlag(page, "done");
    await page.waitForTimeout(TAIL_MS);
    const video = page.video();
    if (!video) throw new ExportError("Playwright recorded no video.");
    await context.close(); // writes the video out
    return { webm: await video.path(), trim: trimSeconds(videoStart, startedAt) };
  } finally {
    await context.close();
  }
}

/** The poster: a still of the map at the replay's peak, from the page itself (sharper than a video frame). */
async function poster(browser: Browser, url: string, out: string): Promise<void> {
  const context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 1 });
  try {
    const page = await context.newPage();
    await page.goto(url);
    await waitForFlag(page, "climax");
    await page.screenshot({ path: out });
  } finally {
    await context.close();
  }
}

async function upload(target: SupabaseTarget, id: string, files: Record<string, string>): Promise<void> {
  for (const kind of EXPORT_KINDS) {
    const req = uploadRequest(target, id, kind);
    let res: Response;
    try {
      res = await fetch(req.url, { method: "POST", headers: req.headers, body: readFileSync(files[kind]) });
    } catch (e) {
      throw new ExportError(`Uploading ${id}.${kind} failed: ${e instanceof Error ? e.name : "error"}.`);
    }
    if (!res.ok) throw new ExportError(`Uploading ${id}.${kind} failed: HTTP ${res.status}.`);
    console.log(`Uploaded ${id}.${kind} to the private bucket.`);
  }
}

const size = (path: string) => `${(statSync(path).size / 1024 / 1024).toFixed(2)} MB`;

async function main(): Promise<void> {
  let opts: ExportOptions;
  try {
    opts = parseExportArgs(process.argv.slice(2), process.env);
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    console.error(USAGE);
    process.exit(2);
  }
  checkFfmpeg();
  const target = opts.upload ? readSupabaseTarget() : null;
  await checkDone(opts);

  mkdirSync(OUT_DIR, { recursive: true });
  const work = mkdtempSync(join(tmpdir(), "heist-export-"));
  const files = {
    mp4: join(OUT_DIR, `${opts.id}.mp4`),
    gif: join(OUT_DIR, `${opts.id}.gif`),
    png: join(OUT_DIR, `${opts.id}.png`),
  };
  const url = recordUrl(opts.base, opts.id);
  const browser = await chromium.launch();
  try {
    console.log(`Filming ${url}`);
    const { webm, trim } = await film(browser, url, work);
    console.log(`Taking the poster frame`);
    await poster(browser, url, files.png);
    await browser.close();

    ffmpeg(mp4Args(webm, trim, files.mp4), "mp4");
    const palette = join(work, "palette.png");
    ffmpeg(paletteArgs(files.mp4, palette), "gif palette");
    ffmpeg(gifArgs(files.mp4, palette, files.gif), "gif");
    console.log(`Trimmed ${trim.toFixed(2)} s of page loading.`);
    for (const kind of EXPORT_KINDS) console.log(`Wrote ${files[kind]} (${size(files[kind])})`);

    if (target) await upload(target, opts.id, files);
  } finally {
    await browser.close();
    rmSync(work, { recursive: true, force: true });
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof ExportError ? e.message : `Export failed: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
