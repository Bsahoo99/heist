// The browser talks to the engine directly (no Next proxy, which can buffer
// the event stream). The engine allows this site's origin through CORS.
import type { Scene } from "./scene.gen";

export const ENGINE_URL = (process.env.NEXT_PUBLIC_ENGINE_URL ?? "http://127.0.0.1:8000").replace(/\/+$/, "");

export const LOST_CONNECTION_COPY = "Lost the connection to the engine. Refresh to pick up where it left off.";
export const UNREACHABLE_COPY = "We couldn't reach the Heist engine. Try again in a moment.";
const UNEXPECTED_COPY = "Something went wrong on our side. Please try again.";

/** One progress update from the engine (engine `ProgressEvent`, hand-written to match). */
export type ProgressEvent = {
  kind: "stage" | "node_found" | "finding" | "done" | "error";
  message: string;
  data: Record<string, unknown>;
};

export type AnalysisStatus = "running" | "done" | "error";

export type Analysis = {
  status: AnalysisStatus;
  scene: Scene | null;
  error: string | null;
  url: string;
};

/** A request the engine refused, with its plain-words reason. `status` is 0 when it was unreachable. */
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Where to reach the engine, and an optional signal to give up early. */
export type RequestOptions = { base?: string; signal?: AbortSignal };

async function request(path: string, init?: RequestInit, opts: RequestOptions = {}): Promise<Response> {
  const base = (opts.base ?? ENGINE_URL).replace(/\/+$/, "");
  try {
    return await fetch(`${base}${path}`, { cache: "no-store", signal: opts.signal, ...init });
  } catch {
    throw new ApiError(UNREACHABLE_COPY, 0);
  }
}

async function errorFrom(res: Response): Promise<ApiError> {
  const body: unknown = await res.json().catch(() => null);
  const message =
    body && typeof body === "object" && "error" in body && typeof body.error === "string" ? body.error : UNEXPECTED_COPY;
  return new ApiError(message, res.status);
}

export async function startAnalysis(url: string): Promise<{ id: string; cached: boolean }> {
  const res = await request("/analyses", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw await errorFrom(res);
  return res.json();
}

/** The analysis record, or null when the engine has no such id (for example after a restart). */
export async function getAnalysis(id: string, opts?: RequestOptions): Promise<Analysis | null> {
  const res = await request(`/analyses/${encodeURIComponent(id)}`, undefined, opts);
  if (res.status === 404) return null;
  if (!res.ok) throw await errorFrom(res);
  return res.json();
}

/**
 * Streams an analysis's events: every past one first, then live ones. Stops
 * after `done` or `error`. A dropped connection is reported once, as an error
 * event in plain words. Returns the unsubscribe function.
 */
export function subscribe(id: string, onEvent: (e: ProgressEvent) => void): () => void {
  const source = new EventSource(`${ENGINE_URL}/analyses/${encodeURIComponent(id)}/events`);
  let open = true;
  const stop = () => {
    open = false;
    source.close();
  };
  source.onmessage = (msg: MessageEvent<string>) => {
    if (!open) return;
    const e = JSON.parse(msg.data) as ProgressEvent;
    if (e.kind === "done" || e.kind === "error") stop();
    onEvent(e);
  };
  // EventSource would quietly reconnect and replay from the start; report it instead.
  source.onerror = () => {
    if (!open) return;
    stop();
    onEvent({ kind: "error", message: LOST_CONNECTION_COPY, data: {} });
  };
  return stop;
}
