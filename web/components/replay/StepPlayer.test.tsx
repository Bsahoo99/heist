import { afterEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { StepPlayer } from "./StepPlayer";
import { replaySteps } from "@/lib/timeline";
import { vulnScene } from "@/tests/helpers/scenes";

afterEach(cleanup);

const steps = replaySteps(vulnScene.findings.find((f) => f.id === "m3-messages")!, vulnScene);

function setup(index = 0, playing = false) {
  const onIndex = vi.fn();
  const onPlayingChange = vi.fn();
  render(
    <>
      <input aria-label="Elsewhere" />
      <StepPlayer steps={steps} index={index} onIndex={onIndex} playing={playing} onPlayingChange={onPlayingChange} />
    </>,
  );
  return { onIndex, onPlayingChange };
}

describe("StepPlayer", () => {
  test("buttons have accessible names", () => {
    setup(0, false);
    expect(screen.getByRole("button", { name: "Play" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Previous step" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Next step" })).toBeTruthy();
    cleanup();
    setup(0, true);
    expect(screen.getByRole("button", { name: "Pause" })).toBeTruthy();
  });

  test("forward and back", () => {
    const { onIndex } = setup(2);
    fireEvent.click(screen.getByRole("button", { name: "Next step" }));
    expect(onIndex).toHaveBeenLastCalledWith(3);
    fireEvent.click(screen.getByRole("button", { name: "Previous step" }));
    expect(onIndex).toHaveBeenLastCalledWith(1);
  });

  test("no step before the first or after the last", () => {
    setup(0);
    expect((screen.getByRole("button", { name: "Previous step" }) as HTMLButtonElement).disabled).toBe(true);
    cleanup();
    setup(steps.length - 1);
    expect((screen.getByRole("button", { name: "Next step" }) as HTMLButtonElement).disabled).toBe(true);
  });

  test("play and pause", () => {
    const { onPlayingChange } = setup(0, false);
    fireEvent.click(screen.getByRole("button", { name: "Play" }));
    expect(onPlayingChange).toHaveBeenLastCalledWith(true);
  });

  test("keyboard: arrows and space when the player has focus", () => {
    const { onIndex, onPlayingChange } = setup(2, false);
    const player = screen.getByRole("group", { name: /step player/i });
    fireEvent.keyDown(player, { key: "ArrowRight" });
    expect(onIndex).toHaveBeenLastCalledWith(3);
    fireEvent.keyDown(player, { key: "ArrowLeft" });
    expect(onIndex).toHaveBeenLastCalledWith(1);
    fireEvent.keyDown(player, { key: " " });
    expect(onPlayingChange).toHaveBeenLastCalledWith(true);
  });

  test("keys typed elsewhere are left alone", () => {
    const { onIndex, onPlayingChange } = setup(2, false);
    const input = screen.getByRole("textbox", { name: "Elsewhere" });
    fireEvent.keyDown(input, { key: "ArrowRight" });
    fireEvent.keyDown(input, { key: " " });
    expect(onIndex).not.toHaveBeenCalled();
    expect(onPlayingChange).not.toHaveBeenCalled();
  });

  test("says where it is", () => {
    setup(3);
    expect(screen.getByText(`Step 4 of ${steps.length}`)).toBeTruthy();
  });
});
