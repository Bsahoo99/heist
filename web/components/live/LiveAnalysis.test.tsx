import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { Analysis, ProgressEvent } from "@/lib/api";
import { vulnScene } from "@/tests/helpers/scenes";

const api = vi.hoisted(() => ({
  getAnalysis: vi.fn(),
  subscribe: vi.fn(),
  listeners: [] as ((e: ProgressEvent) => void)[],
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const real = await importOriginal<typeof import("@/lib/api")>();
  return { ...real, getAnalysis: api.getAnalysis, subscribe: api.subscribe };
});

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

const { LiveAnalysis, GONE_COPY } = await import("./LiveAnalysis");
const { LOST_CONNECTION_COPY } = await import("@/lib/api");

const URL = "https://github.com/a/b";
const running: Analysis = { status: "running", scene: null, error: null, url: URL };

/** The latest stream's listener: sends an event as the engine would. */
const send = async (e: ProgressEvent) => {
  await act(async () => api.listeners.at(-1)!(e));
};
const flush = () => act(async () => {});

beforeEach(() => {
  api.listeners = [];
  api.getAnalysis.mockReset();
  api.subscribe.mockReset().mockImplementation((_id: string, on: (e: ProgressEvent) => void) => {
    api.listeners.push(on);
    return () => {};
  });
});
afterEach(cleanup);

const h1 = () => screen.getByRole("heading", { level: 1 }).textContent;

describe("LiveAnalysis", () => {
  test("live: an h1, the stage line, and the queued copy while waiting for a worker", async () => {
    api.getAnalysis.mockResolvedValue(running);
    render(<LiveAnalysis id="x" />);
    await flush();
    expect(h1()).toBe("Casing a/b");
    await send({ kind: "stage", message: "Waiting for a free crew", data: {} });
    expect(screen.getByTestId("live-stage").textContent).toBe("Waiting for a free crew");
  });

  test("results: the worst finding's title is the h1", async () => {
    api.getAnalysis.mockResolvedValue({ ...running, status: "done", scene: vulnScene });
    render(<LiveAnalysis id="x" />);
    await flush();
    expect(h1()).toBe(vulnScene.findings[0].title);
  });

  test("a failed heist shows the engine's copy under an h1", async () => {
    api.getAnalysis.mockResolvedValue(running);
    render(<LiveAnalysis id="x" />);
    await flush();
    await send({ kind: "error", message: "This stack is not supported yet.", data: {} });
    expect(h1()).toBe("We couldn't run this heist");
    expect(screen.getByText("This stack is not supported yet.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Reload" })).toBeNull();
  });

  test("a dropped stream is a lost connection, and Reload picks it up again", async () => {
    api.getAnalysis.mockResolvedValue(running);
    render(<LiveAnalysis id="x" />);
    await flush();
    await send({ kind: "error", message: LOST_CONNECTION_COPY, data: {} });
    expect(h1()).toBe("Lost the connection");
    expect(screen.getByText(LOST_CONNECTION_COPY)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Try another repo" }).getAttribute("href")).toBe("/");
    fireEvent.click(screen.getByRole("button", { name: "Reload" }));
    await flush();
    expect(api.subscribe).toHaveBeenCalledTimes(2);
    expect(h1()).toBe("Casing a/b");
    await send({ kind: "stage", message: "Planning the heist", data: {} });
    expect(screen.getByTestId("live-stage").textContent).toBe("Planning the heist");
  });

  test("a dropped stream for an id the engine no longer has is gone, not lost", async () => {
    api.getAnalysis.mockResolvedValueOnce(running).mockResolvedValueOnce(null);
    render(<LiveAnalysis id="x" />);
    await flush();
    await send({ kind: "error", message: LOST_CONNECTION_COPY, data: {} });
    await flush();
    expect(h1()).toBe("Nothing here");
    expect(screen.getByText(GONE_COPY)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Reload" })).toBeNull();
  });

  test("an unknown id is gone", async () => {
    api.getAnalysis.mockResolvedValue(null);
    render(<LiveAnalysis id="x" />);
    await flush();
    expect(h1()).toBe("Nothing here");
    expect(api.subscribe).not.toHaveBeenCalled();
  });

  test("an unreachable engine offers Reload", async () => {
    api.getAnalysis.mockRejectedValue(new Error("down"));
    render(<LiveAnalysis id="x" />);
    await flush();
    expect(h1()).toBe("Lost the connection");
    expect(screen.getByRole("button", { name: "Reload" })).toBeTruthy();
  });
});
