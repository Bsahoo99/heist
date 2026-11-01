import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { cleanScene, vulnScene, withProvedFinding } from "@/tests/helpers/scenes";
import type { Exports } from "@/lib/api";
import type { Scene } from "@/lib/scene.gen";
import { fixtureScene } from "@/tests/helpers/fixtureScene";

const api = vi.hoisted(() => ({ getExports: vi.fn(), openUrl: vi.fn() }));

vi.mock("@/lib/api", async (importOriginal) => {
  const real = await importOriginal<typeof import("@/lib/api")>();
  return { ...real, getExports: api.getExports };
});

vi.mock("@/lib/openUrl", () => ({ openUrl: api.openUrl }));

const { ResultsView } = await import("./ResultsView");

const withMeta = (scene: Scene, meta: Partial<Scene["meta"]>): Scene => ({ ...scene, meta: { ...scene.meta, ...meta } });
const BADGE_HEADING = "Add the badge to your README";

const NONE: Exports = { mp4: null, gif: null, png: null };
const SIGNED: Exports = {
  mp4: "https://x.supabase.co/storage/v1/object/sign/exports/abc.mp4?token=t&download=heist-abc.mp4",
  gif: "https://x.supabase.co/storage/v1/object/sign/exports/abc.gif?token=t&download=heist-abc.gif",
  png: "https://x.supabase.co/storage/v1/object/sign/exports/abc.png?token=t",
};
const flush = () => act(async () => {});

beforeEach(() => {
  api.getExports.mockReset().mockResolvedValue(NONE);
  api.openUrl.mockReset();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("ResultsView", () => {
  test("normal layout: replay, player, panel, legend and the findings list", () => {
    const { container } = render(<ResultsView scene={vulnScene} autoPlay={false} />);
    expect(screen.getByRole("group", { name: "Step player" })).toBeTruthy();
    expect(screen.getAllByRole("tab")).toHaveLength(3);
    expect(screen.getByText(`All findings (${vulnScene.findings.length})`)).toBeTruthy();
    expect(screen.getByRole("list", { name: "Map key" })).toBeTruthy();
    expect(container.querySelector(".citymap-wide svg")).not.toBeNull();
  });

  test("record layout: the map and the caption only", () => {
    const { container } = render(<ResultsView scene={vulnScene} id="abc" autoPlay={false} layout="record" />);
    expect(container.querySelector(".results")!.getAttribute("data-layout")).toBe("record");
    expect(container.querySelector(".citymap-wide svg")).not.toBeNull();
    expect(container.querySelector(".replay-caption")).not.toBeNull();
    expect(container.querySelector(".results-head")).toBeNull();
    expect(screen.queryByRole("group", { name: "Step player" })).toBeNull();
    expect(screen.queryAllByRole("tab")).toHaveLength(0);
    expect(screen.queryByText(/All findings/)).toBeNull();
    // Nothing to download in a recording: the engine is not even asked.
    expect(api.getExports).not.toHaveBeenCalled();
  });

  test("the replay says whether it is playing", () => {
    render(<ResultsView scene={vulnScene} autoPlay={false} />);
    expect(screen.getByTestId("replay").getAttribute("data-state")).toBe("paused");
    cleanup();
    render(<ResultsView scene={vulnScene} />);
    expect(screen.getByTestId("replay").getAttribute("data-state")).toBe("playing");
  });

  test("the map box is a labelled group", () => {
    render(<ResultsView scene={cleanScene} autoPlay={false} />);
    expect(screen.getByRole("group", { name: /Heist replay/ })).toBeTruthy();
  });

  test("a proved finding's player has a proof step", () => {
    const { scene, finding } = withProvedFinding(vulnScene);
    const { container } = render(<ResultsView scene={scene} initialFindingId={finding.id} autoPlay={false} />);
    const segs = container.querySelectorAll(".step-seg");
    expect(segs[segs.length - 1].getAttribute("data-kind")).toBe("proof");
  });

  test("the selected finding's fix sits under the step panel", () => {
    render(<ResultsView scene={vulnScene} autoPlay={false} />);
    expect(screen.getByRole("heading", { name: "How to fix it" })).toBeTruthy();
    expect(screen.getByText(vulnScene.findings[0].fix.explanation)).toBeTruthy();
  });

  test("record layout: no fix, rules or badge cards", () => {
    render(<ResultsView scene={withMeta(vulnScene, { has_db_rules: false })} autoPlay={false} layout="record" />);
    expect(screen.queryByRole("heading", { name: "How to fix it" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "We can't see your database rules" })).toBeNull();
    cleanup();
    render(<ResultsView scene={cleanScene} id="abc" autoPlay={false} layout="record" />);
    expect(screen.queryByRole("heading", { name: BADGE_HEADING })).toBeNull();
  });

  test("record layout: flags started, the climax, then done once the end card has held", async () => {
    vi.useFakeTimers();
    const flags = document.body.dataset;
    render(<ResultsView scene={vulnScene} layout="record" />);
    await act(() => vi.advanceTimersByTimeAsync(50));
    // The first frame's own wall-clock time, in epoch ms.
    expect(flags.started).toMatch(/^\d{13}$/);
    expect(Math.abs(Number(flags.started) - Date.now())).toBeLessThan(1_000);
    expect(flags.climax).toBeUndefined();
    expect(flags.done).toBeUndefined();
    // Past the end of the replay (at most 30 s): the end card shows, with nothing to click.
    await act(() => vi.advanceTimersByTimeAsync(31_000));
    expect(screen.getByTestId("replay").getAttribute("data-state")).toBe("ended");
    expect(flags.climax).toBe("true");
    expect(screen.getByTestId("replay-end-title").textContent).toBe(vulnScene.findings[0].title);
    expect(screen.queryByRole("button", { name: "Watch again" })).toBeNull();
    expect(flags.done).toBeUndefined();
    await act(() => vi.advanceTimersByTimeAsync(1_000));
    expect(flags.done).toBe("true");
    cleanup();
    expect(flags.started).toBeUndefined();
    expect(flags.done).toBeUndefined();
  });

  test("normal layout sets no record flags", async () => {
    vi.useFakeTimers();
    render(<ResultsView scene={vulnScene} />);
    await act(() => vi.advanceTimersByTimeAsync(32_000));
    expect(screen.getByTestId("replay").getAttribute("data-state")).toBe("ended");
    expect(document.body.dataset.started).toBeUndefined();
    expect(document.body.dataset.done).toBeUndefined();
  });

  test("downloads: MP4 and GIF links at the top of the list when exported", async () => {
    api.getExports.mockResolvedValue(SIGNED);
    const { container } = render(<ResultsView scene={vulnScene} id="abc" autoPlay={false} />);
    await flush();
    expect(api.getExports).toHaveBeenCalledTimes(1);
    expect(api.getExports).toHaveBeenCalledWith("abc");
    const mp4 = screen.getByRole("link", { name: "Download MP4" });
    expect(mp4.getAttribute("href")).toBe(SIGNED.mp4);
    expect(screen.getByRole("link", { name: "Download GIF" }).getAttribute("href")).toBe(SIGNED.gif);
    const list = container.querySelector(".results-list")!;
    expect(list.contains(mp4)).toBe(true);
    expect(mp4.compareDocumentPosition(screen.getByText(/All findings/)) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  test("downloads: under the badge on a clean run", async () => {
    api.getExports.mockResolvedValue({ ...SIGNED, gif: null });
    const { container } = render(<ResultsView scene={cleanScene} id="abc" autoPlay={false} />);
    await flush();
    const mp4 = screen.getByRole("link", { name: "Download MP4" });
    const badge = screen.getByRole("heading", { name: BADGE_HEADING });
    expect(container.querySelector(".results-panel")!.contains(mp4)).toBe(true);
    expect(badge.compareDocumentPosition(mp4) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.queryByRole("link", { name: "Download GIF" })).toBeNull();
  });

  test("downloads: nothing when nothing was exported, or the engine fails", async () => {
    render(<ResultsView scene={vulnScene} id="abc" autoPlay={false} />);
    await flush();
    expect(screen.queryByRole("link", { name: /Download/ })).toBeNull();
    cleanup();
    api.getExports.mockRejectedValue(new Error("down"));
    render(<ResultsView scene={vulnScene} id="abc" autoPlay={false} />);
    await flush();
    expect(screen.queryByRole("link", { name: /Download/ })).toBeNull();
    expect(document.querySelector(".export-links")).toBeNull();
  });

  test("downloads: a click on young links just follows them", async () => {
    api.getExports.mockResolvedValue(SIGNED);
    render(<ResultsView scene={vulnScene} id="abc" autoPlay={false} />);
    await flush();
    const mp4 = screen.getByRole("link", { name: "Download MP4" });
    // jsdom does not navigate; the point is that the default action is left alone.
    const clicked = fireEvent.click(mp4);
    expect(clicked).toBe(true);
    expect(api.getExports).toHaveBeenCalledTimes(1);
    expect(api.openUrl).not.toHaveBeenCalled();
  });

  test("downloads: links older than 50 minutes are signed again on click", async () => {
    const start = Date.now();
    const now = vi.spyOn(Date, "now").mockReturnValue(start);
    api.getExports.mockResolvedValueOnce(SIGNED);
    render(<ResultsView scene={vulnScene} id="abc" autoPlay={false} />);
    await flush();
    const fresh = { ...SIGNED, gif: SIGNED.gif!.replace("token=t", "token=new") };
    api.getExports.mockResolvedValueOnce(fresh);
    now.mockReturnValue(start + 51 * 60 * 1000);
    const clicked = fireEvent.click(screen.getByRole("link", { name: "Download GIF" }));
    expect(clicked).toBe(false); // the stale link is not followed
    await flush();
    expect(api.getExports).toHaveBeenCalledTimes(2);
    expect(api.openUrl).toHaveBeenCalledWith(fresh.gif);
    expect(screen.getByRole("link", { name: "Download GIF" }).getAttribute("href")).toBe(fresh.gif);
    now.mockRestore();
  });

  test("downloads: a failed refresh opens nothing", async () => {
    const start = Date.now();
    const now = vi.spyOn(Date, "now").mockReturnValue(start);
    api.getExports.mockResolvedValueOnce(SIGNED);
    render(<ResultsView scene={vulnScene} id="abc" autoPlay={false} />);
    await flush();
    api.getExports.mockRejectedValueOnce(new Error("down"));
    now.mockReturnValue(start + 51 * 60 * 1000);
    fireEvent.click(screen.getByRole("link", { name: "Download MP4" }));
    await flush();
    expect(api.openUrl).not.toHaveBeenCalled();
    now.mockRestore();
  });

  test("downloads: pages without an id never ask", async () => {
    render(<ResultsView scene={vulnScene} autoPlay={false} />);
    await flush();
    expect(api.getExports).not.toHaveBeenCalled();
  });

  test("missing rules: the card comes before the findings list, in its own grid area", () => {
    const { container } = render(
      <ResultsView scene={withMeta(vulnScene, { has_db_rules: false })} id="abc" autoPlay={false} />,
    );
    const card = screen.getByRole("heading", { name: "We can't see your database rules" });
    expect(container.querySelector(".results-rules")!.contains(card)).toBe(true);
    expect(container.querySelector(".results-list")!.contains(card)).toBe(false);
    expect(container.querySelector(".results-panel")!.contains(card)).toBe(false);
    // Phones show the grid areas in source order: the card, then the list.
    expect(card.compareDocumentPosition(screen.getByText(/All findings/)) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.queryByRole("heading", { name: BADGE_HEADING })).toBeNull();
  });

  test("missing rules on a clean run: no claim that every lock held, no badge", () => {
    render(<ResultsView scene={withMeta(cleanScene, { has_db_rules: false })} id="abc" autoPlay={false} />);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("No way in through the code");
    expect(screen.getByText(/could not check your database rules/)).toBeTruthy();
    expect(screen.queryByText("Every lock held")).toBeNull();
    expect(screen.getByRole("heading", { name: "We can't see your database rules" })).toBeTruthy();
    expect(screen.queryByText(/No findings\. Every check passed/)).toBeNull();
    expect(screen.queryByRole("heading", { name: BADGE_HEADING })).toBeNull();
  });

  test("clean run with an id: the badge block in the results panel", () => {
    const { container } = render(<ResultsView scene={cleanScene} id="abc" autoPlay={false} />);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Every lock held");
    const block = screen.getByRole("heading", { name: BADGE_HEADING }).closest("section")!;
    expect(container.querySelector(".results-panel")!.contains(block)).toBe(true);
    expect(screen.getByTestId("badge-markdown").textContent).toBe(
      `[![Heist-tested](${window.location.origin}/api/badge/abc)](${window.location.origin}/a/abc)`,
    );
    expect(screen.getByRole("img", { name: "Heist-tested: 7/7 locks held" }).getAttribute("src")).toBe("/api/badge/abc");
    expect(screen.getByRole("button", { name: "Copy badge" })).toBeTruthy();
  });

  test("no id (dev pages): no badge block", () => {
    render(<ResultsView scene={cleanScene} autoPlay={false} />);
    expect(screen.queryByRole("heading", { name: BADGE_HEADING })).toBeNull();
  });

  test("only possible findings with every check held: the badge above the list", () => {
    const scene = withMeta(vulnScene, { checks_held: 7 });
    const { container } = render(<ResultsView scene={scene} id="abc" autoPlay={false} />);
    const block = screen.getByRole("heading", { name: BADGE_HEADING });
    expect(container.querySelector(".results-list")!.contains(block)).toBe(true);
  });

  test("a failing app offers no badge", () => {
    render(<ResultsView scene={vulnScene} id="abc" autoPlay={false} />);
    expect(screen.queryByRole("heading", { name: BADGE_HEADING })).toBeNull();
  });

  test("migrations it could not read: no claim that every lock held, no badge", () => {
    const scene = withMeta(cleanScene, { unparsed_migrations: ["supabase/migrations/0009_a.sql", "supabase/migrations/0010_b.sql"] });
    const { container } = render(<ResultsView scene={scene} id="abc" autoPlay={false} />);
    const head = container.querySelector(".results-head")!.textContent!;
    expect(head).not.toMatch(/every lock|all seven/i);
    expect(head).toContain("2 migration files could not be read, so the database checks may be incomplete.");
    expect(screen.queryByText(/Every check passed/)).toBeNull();
    expect(screen.getByText("No findings in the parts Heist could read.")).toBeTruthy();
    expect(screen.queryByRole("heading", { name: BADGE_HEADING })).toBeNull();
  });

  test("a clean run with no door to try ends at once", async () => {
    const base = fixtureScene({ guard_desk: false, side_doors: false });
    const scene = withMeta(base, { has_db_rules: false, checks_tested: 5 });
    render(<ResultsView scene={scene} />);
    await waitFor(() => expect(screen.getByTestId("replay").getAttribute("data-state")).toBe("ended"), { timeout: 1000 });
    expect(screen.getByTestId("replay-end-title").textContent).toBe("No way in through the code.");
  });
});
