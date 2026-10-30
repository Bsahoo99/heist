import { afterEach, describe, expect, test } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ResultsView } from "./ResultsView";
import { cleanScene, vulnScene, withProvedFinding } from "@/tests/helpers/scenes";
import type { Scene } from "@/lib/scene.gen";

const withMeta = (scene: Scene, meta: Partial<Scene["meta"]>): Scene => ({ ...scene, meta: { ...scene.meta, ...meta } });
const BADGE_HEADING = "Add the badge to your README";

afterEach(cleanup);

describe("ResultsView", () => {
  test("normal layout: replay, player, panel, legend and the findings list", () => {
    const { container } = render(<ResultsView scene={vulnScene} autoPlay={false} />);
    expect(screen.getByRole("group", { name: "Step player" })).toBeTruthy();
    expect(screen.getAllByRole("tab")).toHaveLength(3);
    expect(screen.getByText(`All findings (${vulnScene.findings.length})`)).toBeTruthy();
    expect(screen.getByRole("list", { name: "Map key" })).toBeTruthy();
    expect(container.querySelector(".citymap-wide svg")).not.toBeNull();
  });

  test("video layout: header line, map, caption and player only", () => {
    const { container } = render(<ResultsView scene={vulnScene} autoPlay={false} layout="video" />);
    expect(container.querySelector(".results")!.getAttribute("data-layout")).toBe("video");
    expect(screen.getByRole("heading", { name: vulnScene.findings[0].title })).toBeTruthy();
    expect(screen.getByRole("group", { name: "Step player" })).toBeTruthy();
    expect(container.querySelector(".replay-caption")).not.toBeNull();
    expect(screen.queryAllByRole("tab")).toHaveLength(0);
    expect(screen.queryByText(/All findings/)).toBeNull();
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

  test("video layout: no fix, rules or badge cards", () => {
    render(<ResultsView scene={withMeta(vulnScene, { has_db_rules: false })} autoPlay={false} layout="video" />);
    expect(screen.queryByRole("heading", { name: "How to fix it" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "We can't see your database rules" })).toBeNull();
    cleanup();
    render(<ResultsView scene={cleanScene} id="abc" autoPlay={false} layout="video" />);
    expect(screen.queryByRole("heading", { name: BADGE_HEADING })).toBeNull();
  });

  test("missing rules: the card sits above the findings list", () => {
    const { container } = render(
      <ResultsView scene={withMeta(vulnScene, { has_db_rules: false })} id="abc" autoPlay={false} />,
    );
    const list = container.querySelector(".results-list")!;
    const card = screen.getByRole("heading", { name: "We can't see your database rules" });
    expect(list.contains(card)).toBe(true);
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
});
