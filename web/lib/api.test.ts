import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, ENGINE_URL, LOST_CONNECTION_COPY, getAnalysis, startAnalysis, subscribe, type ProgressEvent } from "./api";

class FakeEventSource {
  static last: FakeEventSource | null = null;
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  closed = false;
  constructor(public url: string) {
    FakeEventSource.last = this;
  }
  close() {
    this.closed = true;
  }
  send(e: ProgressEvent) {
    this.onmessage?.(new MessageEvent("message", { data: JSON.stringify(e) }));
  }
  fail() {
    this.onerror?.(new Event("error"));
  }
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

beforeEach(() => {
  vi.stubGlobal("EventSource", FakeEventSource);
});
afterEach(() => {
  vi.unstubAllGlobals();
  FakeEventSource.last = null;
});

describe("startAnalysis", () => {
  it("posts the url and returns the id", async () => {
    const fetch = vi.fn().mockResolvedValue(json(200, { id: "abc", cached: false }));
    vi.stubGlobal("fetch", fetch);
    await expect(startAnalysis("https://github.com/a/b")).resolves.toEqual({ id: "abc", cached: false });
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe(`${ENGINE_URL}/analyses`);
    expect(init).toMatchObject({ method: "POST", body: JSON.stringify({ url: "https://github.com/a/b" }) });
  });

  it("throws the engine's plain error copy with the status", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(400, { error: "Paste a public GitHub repo URL." })));
    const err = await startAnalysis("https://gitlab.com/a/b").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 400, message: "Paste a public GitHub repo URL." });
  });

  it("says the engine is unreachable when fetch fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const err = await startAnalysis("https://github.com/a/b").catch((e: unknown) => e);
    expect(err).toMatchObject({ status: 0, message: expect.stringMatching(/reach/) });
  });
});

describe("getAnalysis", () => {
  it("returns the record, or null for an unknown id", async () => {
    const body = { status: "running", scene: null, error: null, url: "https://github.com/a/b" };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(json(200, body)).mockResolvedValueOnce(json(404, { error: "gone" })));
    await expect(getAnalysis("abc")).resolves.toEqual(body);
    await expect(getAnalysis("nope")).resolves.toBeNull();
  });

  it("encodes the id in the path", async () => {
    const fetch = vi.fn().mockResolvedValue(json(404, { error: "gone" }));
    vi.stubGlobal("fetch", fetch);
    await getAnalysis("a/b?c");
    expect(fetch.mock.calls[0][0]).toBe(`${ENGINE_URL}/analyses/a%2Fb%3Fc`);
  });
});

describe("subscribe", () => {
  it("passes events through and closes after done", () => {
    const seen: ProgressEvent[] = [];
    subscribe("abc", (e) => seen.push(e));
    const es = FakeEventSource.last!;
    expect(es.url).toBe(`${ENGINE_URL}/analyses/abc/events`);
    es.send({ kind: "stage", message: "Mapping the app", data: {} });
    es.send({ kind: "done", message: "Done", data: {} });
    expect(seen.map((e) => e.kind)).toEqual(["stage", "done"]);
    expect(es.closed).toBe(true);
    // The server closing the stream afterwards is not a lost connection.
    es.fail();
    expect(seen).toHaveLength(2);
  });

  it("closes after an error event", () => {
    const seen: ProgressEvent[] = [];
    subscribe("abc", (e) => seen.push(e));
    FakeEventSource.last!.send({ kind: "error", message: "Not supported yet", data: {} });
    expect(FakeEventSource.last!.closed).toBe(true);
    expect(seen).toEqual([{ kind: "error", message: "Not supported yet", data: {} }]);
  });

  it("reports a dropped connection once, in plain words", () => {
    const seen: ProgressEvent[] = [];
    subscribe("abc", (e) => seen.push(e));
    FakeEventSource.last!.fail();
    FakeEventSource.last!.fail();
    expect(seen).toEqual([{ kind: "error", message: LOST_CONNECTION_COPY, data: {} }]);
    expect(FakeEventSource.last!.closed).toBe(true);
    expect(LOST_CONNECTION_COPY).toBe("Lost the connection to the engine. Refresh to pick up where it left off.");
  });

  it("stops delivering after unsubscribe", () => {
    const seen: ProgressEvent[] = [];
    const off = subscribe("abc", (e) => seen.push(e));
    off();
    expect(FakeEventSource.last!.closed).toBe(true);
    FakeEventSource.last!.send({ kind: "stage", message: "late", data: {} });
    FakeEventSource.last!.fail();
    expect(seen).toEqual([]);
  });
});
