import { afterEach, describe, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FixCard } from "./FixCard";
import { vulnScene } from "@/tests/helpers/scenes";

const clipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");

afterEach(() => {
  cleanup();
  if (clipboard) Object.defineProperty(navigator, "clipboard", clipboard);
  else Reflect.deleteProperty(navigator, "clipboard");
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const f = vulnScene.findings[0];

describe("FixCard", () => {
  test("explanation, diff and the copy button", () => {
    const { container } = render(<FixCard fix={f.fix} />);
    expect(screen.getByRole("heading", { name: "How to fix it" })).toBeTruthy();
    expect(screen.getByText(f.fix.explanation)).toBeTruthy();
    const diff = container.querySelector(".fix-diff")!;
    expect(diff.textContent).toBe(f.fix.diff);
    expect(screen.getByRole("button", { name: "Copy fix prompt" })).toBeTruthy();
  });

  test("tints added and removed lines", () => {
    const fix = { ...f.fix, diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n same" };
    const { container } = render(<FixCard fix={fix} />);
    const kinds = [...container.querySelectorAll(".fix-diff [data-line]")].map((el) => el.getAttribute("data-line"));
    expect(kinds).toEqual(["file", "file", "hunk", "del", "add", "ctx"]);
  });

  test("copy fix prompt copies exact prompt", async () => {
    const user = userEvent.setup();
    render(<FixCard fix={f.fix} />);
    await user.click(screen.getByRole("button", { name: "Copy fix prompt" }));
    expect(await navigator.clipboard.readText()).toBe(f.fix.prompt);
    expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy();
  });

  test("says Copied for about two seconds", async () => {
    vi.useFakeTimers();
    const write = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText: write }, configurable: true });
    render(<FixCard fix={f.fix} />);
    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Copy fix prompt" })));
    expect(write).toHaveBeenCalledWith(f.fix.prompt);
    expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy();
    await act(() => vi.advanceTimersByTimeAsync(1500));
    expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy();
    await act(() => vi.advanceTimersByTimeAsync(600));
    expect(screen.getByRole("button", { name: "Copy fix prompt" })).toBeTruthy();
  });

  test("a failed copy reveals the prompt to select", async () => {
    const user = userEvent.setup();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));
    render(<FixCard fix={f.fix} />);
    expect(screen.queryByTestId("fix-prompt")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Copy fix prompt" }));
    expect(screen.getByText("Copy failed, select the text below")).toBeTruthy();
    expect(screen.getByTestId("fix-prompt").textContent).toBe(f.fix.prompt);
  });

  test("no clipboard at all (insecure page) fails the same way, without throwing", async () => {
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
    render(<FixCard fix={f.fix} />);
    await user.click(screen.getByRole("button", { name: "Copy fix prompt" }));
    expect(screen.getByText("Copy failed, select the text below")).toBeTruthy();
  });

  test("hides the parts that are empty", () => {
    const { container, rerender } = render(<FixCard fix={{ ...f.fix, diff: "" }} />);
    expect(container.querySelector(".fix-diff")).toBeNull();
    rerender(<FixCard fix={{ ...f.fix, prompt: "" }} />);
    expect(screen.queryByRole("button", { name: "Copy fix prompt" })).toBeNull();
    rerender(<FixCard fix={{ explanation: "", diff: "", prompt: "" }} />);
    expect(container.innerHTML).toBe("");
  });
});
