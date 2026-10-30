import { afterEach, describe, expect, test, vi } from "vitest";
import { GET } from "./route";
import { cleanScene, vulnScene } from "@/tests/helpers/scenes";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

const call = (id: string) => GET(new Request(`http://localhost/api/badge/${id}`), { params: Promise.resolve({ id }) });

function engine(res: () => Response | Promise<Response>) {
  const fetchMock = vi.fn(async () => res());
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("GET /api/badge/[id]", () => {
  test("a done analysis is an SVG badge cached for an hour", async () => {
    const fetchMock = engine(() => json({ status: "done", scene: cleanScene, error: null, url: "x" }));
    const res = await call("abc");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/svg+xml; charset=utf-8");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
    const body = await res.text();
    expect(body).toContain("7/7 locks held");
    expect(String(fetchMock.mock.calls[0][0 as never])).toMatch(/\/analyses\/abc$/);
  });

  test("counts the held checks of a failing app", async () => {
    engine(() => json({ status: "done", scene: vulnScene, error: null, url: "x" }));
    expect(await (await call("v")).text()).toContain(`${vulnScene.meta.checks_held}/7 locks held`);
  });

  test("uses the server-only engine URL when set", async () => {
    vi.stubEnv("HEIST_ENGINE_URL", "http://engine.internal:9000/");
    const fetchMock = engine(() => json({ status: "done", scene: cleanScene, error: null, url: "x" }));
    await call("abc");
    expect(String(fetchMock.mock.calls[0][0 as never])).toBe("http://engine.internal:9000/analyses/abc");
  });

  test.each([
    ["an unknown id", () => json({ error: "nope" }, 404)],
    ["a running analysis", () => json({ status: "running", scene: null, error: null, url: "x" })],
    ["a failed analysis", () => json({ status: "error", scene: null, error: "bad", url: "x" })],
    ["an engine error", () => json({ error: "boom" }, 500)],
    [
      "an unreachable engine",
      () => {
        throw new TypeError("fetch failed");
      },
    ],
  ])("%s is a 404 that is never cached", async (_name, res) => {
    engine(res);
    const out = await call("abc");
    expect(out.status).toBe(404);
    expect(out.headers.get("Cache-Control")).toBe("no-store");
    expect(out.headers.get("Content-Type")).toMatch(/^text\/plain/);
  });

  test.each(["..", ".", "a.b", "has space", "x".repeat(65), "%2e%2e"])("an id like %j is a 404 without asking the engine", async (id) => {
    const fetchMock = engine(() => json({ status: "done", scene: cleanScene, error: null, url: "x" }));
    const out = await call(id);
    expect(out.status).toBe(404);
    expect(out.headers.get("Cache-Control")).toBe("no-store");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test("an engine that cannot be reached is logged once by error type, without the id", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    engine(() => {
      throw new TypeError("fetch failed for http://engine/analyses/secret-id");
    });
    await call("secret-id");
    expect(log).toHaveBeenCalledTimes(1);
    const line = log.mock.calls[0].join(" ");
    expect(line).toContain("TypeError");
    expect(line).not.toContain("secret-id");
  });

  test("an unknown or unfinished analysis is not logged", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    engine(() => json({ error: "nope" }, 404));
    await call("abc");
    engine(() => json({ status: "running", scene: null, error: null, url: "x" }));
    await call("abc");
    expect(log).not.toHaveBeenCalled();
  });
});
