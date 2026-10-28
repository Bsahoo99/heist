import { afterEach, describe, expect, test } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ResultsView } from "./ResultsView";
import { cleanScene, vulnScene, withProvedFinding } from "@/tests/helpers/scenes";

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
});
