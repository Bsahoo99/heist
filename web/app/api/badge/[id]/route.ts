import { ENGINE_URL, getAnalysis } from "@/lib/api";
import { badgeSvg, badgeText, badgeTone } from "@/lib/badge";

/** Engine ids are `secrets.token_urlsafe(9)`; anything else never reaches the engine. */
const ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Give up on the engine after this long, so a stuck engine never holds a README image open. */
const ENGINE_TIMEOUT_MS = 5_000;

function notFound(): Response {
  return new Response("No finished analysis with this id.\n", {
    status: 404,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function errorKind(err: unknown): string {
  if (!(err instanceof Error)) return typeof err;
  const cause = err.cause instanceof Error ? ` (${err.cause.name})` : "";
  const status = "status" in err && typeof err.status === "number" && err.status > 0 ? ` ${err.status}` : "";
  return `${err.name}${status}${cause}`;
}

/**
 * The README badge for one analysis, as an SVG. Only a finished analysis has
 * one; anything else (unknown id, still running, failed, engine unreachable)
 * is a 404 that is never cached, so the badge appears once the run is done.
 *
 * The engine is asked server side: `HEIST_ENGINE_URL` when set (an address only
 * the server can reach), else the same URL the browser uses.
 */
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  if (!ID.test(id)) return notFound();
  const base = process.env.HEIST_ENGINE_URL || ENGINE_URL;
  const analysis = await getAnalysis(id, { base, signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS) }).catch(
    (err: unknown) => {
      // Error types only: no URL (it holds the id) and nothing from the engine's body.
      console.error(`[badge] engine request failed: ${errorKind(err)}`);
      return null;
    },
  );
  if (analysis?.status !== "done" || !analysis.scene) return notFound();
  const scene = analysis.scene;
  return new Response(badgeSvg(badgeText(scene), badgeTone(scene)), {
    status: 200,
    headers: { "Content-Type": "image/svg+xml; charset=utf-8", "Cache-Control": "public, max-age=3600" },
  });
}
