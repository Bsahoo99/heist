import { afterEach, describe, expect, test } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { StepPanel } from "./StepPanel";
import type { PathStep } from "@/lib/scene.gen";
import { vulnScene } from "@/tests/helpers/scenes";

afterEach(cleanup);

const vaultStep = vulnScene.findings.find((f) => f.id === "m3-messages")!.attack_path[2];
const streetStep = vulnScene.findings.find((f) => f.id === "m3-messages")!.attack_path[0];

describe("StepPanel", () => {
  test("story tab is default and tabs switch", () => {
    render(<StepPanel step={vaultStep} />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Story", "Why", "Code"]);
    expect(screen.getByRole("tab", { name: "Story" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tabpanel").textContent).toContain(vaultStep.story);

    fireEvent.click(screen.getByRole("tab", { name: "Why" }));
    expect(screen.getByRole("tab", { name: "Why" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tabpanel").textContent).toContain(vaultStep.why);
    expect(screen.getByRole("tabpanel").textContent).not.toContain(vaultStep.story);
  });

  test("code tab shows file:start-end, the snippet and the data", () => {
    render(<StepPanel step={vaultStep} />);
    fireEvent.click(screen.getByRole("tab", { name: "Code" }));
    const panel = screen.getByRole("tabpanel");
    expect(panel.textContent).toContain("supabase/migrations/0001_init.sql:37-41");
    expect(panel.querySelector("pre")!.textContent).toBe(vaultStep.code);
    expect(panel.textContent).toContain(vaultStep.data);
  });

  test("code tab omits the location when ref is null", () => {
    render(<StepPanel step={streetStep} />);
    fireEvent.click(screen.getByRole("tab", { name: "Code" }));
    const panel = screen.getByRole("tabpanel");
    expect(panel.textContent).not.toMatch(/:\d+-\d+/);
    expect(panel.querySelector("pre")!.textContent).toBe(streetStep.code);
  });

  test("arrow keys move between tabs", () => {
    render(<StepPanel step={vaultStep} />);
    const story = screen.getByRole("tab", { name: "Story" });
    fireEvent.keyDown(story, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Why" }).getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(screen.getByRole("tab", { name: "Why" }), { key: "ArrowLeft" });
    fireEvent.keyDown(story, { key: "ArrowLeft" });
    expect(screen.getByRole("tab", { name: "Code" }).getAttribute("aria-selected")).toBe("true");
  });

  test("model text is shown as text, never as HTML", () => {
    const evil: PathStep = { ...vaultStep, story: "<img src=x onerror=alert(1)><b>bold</b>", code: "<script>x</script>" };
    const { container } = render(<StepPanel step={evil} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByRole("tabpanel").textContent).toContain("<b>bold</b>");
    fireEvent.click(screen.getByRole("tab", { name: "Code" }));
    expect(container.querySelector("script")).toBeNull();
  });
});
