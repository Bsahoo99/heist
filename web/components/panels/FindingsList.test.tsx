import { afterEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { FindingsList } from "./FindingsList";
import { provedFinding, vulnScene } from "@/tests/helpers/scenes";

afterEach(cleanup);

const findings = [provedFinding, ...vulnScene.findings.filter((f) => f.id !== provedFinding.id)];

describe("FindingsList", () => {
  test("one row per finding, in order", () => {
    render(<FindingsList findings={findings} selectedId={null} onSelect={() => {}} />);
    const rows = screen.getAllByRole("listitem");
    expect(rows).toHaveLength(findings.length);
    expect(rows[1].textContent).toContain(findings[1].title);
  });

  test("status badges: confirmed, proved, and possible drawn dashed", () => {
    render(<FindingsList findings={findings} selectedId={null} onSelect={() => {}} />);
    const proved = screen.getByTestId(`finding-${provedFinding.id}`);
    expect(proved.getAttribute("data-status")).toBe("proved");
    expect(within(proved).getByText("Proved")).toBeTruthy();

    const confirmed = screen.getByTestId("finding-m3-messages");
    expect(within(confirmed).getByText("Confirmed")).toBeTruthy();

    const possible = screen.getByTestId("finding-m3-pets");
    expect(possible.getAttribute("data-status")).toBe("possible");
    expect(possible.className).toContain("border-dashed");
    expect(within(possible).getByText("Possible, not confirmed")).toBeTruthy();
    expect(confirmed.className).not.toContain("border-dashed");
  });

  test("selecting a finding", () => {
    const onSelect = vi.fn();
    render(<FindingsList findings={findings} selectedId="m3-messages" onSelect={onSelect} />);
    const selected = screen.getByTestId("finding-m3-messages");
    expect(selected.getAttribute("aria-current")).toBe("true");
    fireEvent.click(screen.getByTestId("finding-m5-send-email"));
    expect(onSelect).toHaveBeenCalledWith("m5-send-email");
  });

  test("empty list says every check passed", () => {
    render(<FindingsList findings={[]} selectedId={null} onSelect={() => {}} />);
    expect(screen.getByText(/No findings/)).toBeTruthy();
  });
});
