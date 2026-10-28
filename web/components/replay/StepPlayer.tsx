"use client";

import type { KeyboardEvent } from "react";
import type { ReplayStep } from "@/lib/timeline";

type Controls = {
  index: number;
  count: number;
  playing: boolean;
  onIndex: (i: number) => void;
  onPlayingChange: (playing: boolean) => void;
};

const TYPING = new Set(["INPUT", "TEXTAREA", "SELECT"]);

/**
 * Left and Right step, Space plays or pauses. Attach it to an element that
 * holds focus (the player, the map): keys typed anywhere else are untouched.
 * Space and Enter on a focused button keep their normal click.
 */
export function handleStepKeys(e: KeyboardEvent<HTMLElement>, c: Controls): void {
  if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey) return;
  const target = e.target as HTMLElement;
  if (TYPING.has(target.tagName) || target.isContentEditable) return;
  if (target.getAttribute("role") === "tab") return;
  if (e.key === "ArrowRight") {
    e.preventDefault();
    if (c.index < c.count - 1) c.onIndex(c.index + 1);
  } else if (e.key === "ArrowLeft") {
    e.preventDefault();
    if (c.index > 0) c.onIndex(c.index - 1);
  } else if (e.key === " " || e.key === "Spacebar") {
    if (target.tagName === "BUTTON") return;
    e.preventDefault();
    c.onPlayingChange(!c.playing);
  }
}

const KIND_LABEL: Record<ReplayStep["kind"], string> = {
  ghost: "How it should work",
  attack: "How they get in",
  "lock-held": "Testing the locks",
  proof: "The proof",
};

/** Play, pause, step back and forward through a replay's steps. */
export function StepPlayer({
  steps,
  index,
  onIndex,
  playing,
  onPlayingChange,
  ended = false,
}: {
  steps: ReplayStep[];
  index: number;
  onIndex: (i: number) => void;
  playing: boolean;
  onPlayingChange: (playing: boolean) => void;
  /** The replay has finished: say so instead of naming the last step. */
  ended?: boolean;
}) {
  const count = steps.length;
  const controls = { index, count, playing, onIndex, onPlayingChange };
  const current = steps[index];
  return (
    <div
      role="group"
      aria-label="Step player"
      className="step-player"
      onKeyDown={(e) => handleStepKeys(e, controls)}
    >
      <div className="step-player-buttons">
        <button
          type="button"
          className="player-btn"
          aria-label="Previous step"
          disabled={index <= 0}
          onClick={() => onIndex(index - 1)}
        >
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <path d="M5 4v12M16 4 7.5 10 16 16z" />
          </svg>
        </button>
        <button
          type="button"
          className="player-btn player-btn-main"
          aria-label={playing ? "Pause" : "Play"}
          onClick={() => onPlayingChange(!playing)}
        >
          {playing ? (
            <svg viewBox="0 0 20 20" aria-hidden="true">
              <path d="M6 4h3v12H6zM11 4h3v12h-3z" />
            </svg>
          ) : (
            <svg viewBox="0 0 20 20" aria-hidden="true">
              <path d="M6 3.5 16.5 10 6 16.5z" />
            </svg>
          )}
        </button>
        <button
          type="button"
          className="player-btn"
          aria-label="Next step"
          disabled={index >= count - 1}
          onClick={() => onIndex(index + 1)}
        >
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <path d="M15 4v12M4 4l8.5 6L4 16z" />
          </svg>
        </button>
      </div>
      <div className="step-player-track">
        <div className="step-player-segments">
          {steps.map((s, i) => (
            <button
              key={i}
              type="button"
              tabIndex={-1}
              aria-label={`Go to step ${i + 1}`}
              aria-current={i === index && !ended ? "step" : undefined}
              data-kind={s.kind}
              data-done={i < index || ended}
              className="step-seg"
              onClick={() => onIndex(i)}
            />
          ))}
        </div>
        <p className="step-player-where" aria-live="polite">
          {ended ? (
            <span>End of replay</span>
          ) : (
            <>
              <span>{`Step ${index + 1} of ${count}`}</span>
              {current && <span className="step-player-kind">{KIND_LABEL[current.kind]}</span>}
            </>
          )}
        </p>
      </div>
    </div>
  );
}
