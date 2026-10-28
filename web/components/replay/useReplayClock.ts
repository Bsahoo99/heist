"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useMotionValue, type MotionValue } from "motion/react";
import { arrivalTime, eventIndexAt, type TimelineEvent } from "@/lib/timeline";

export type ReplayClock = {
  timeline: TimelineEvent[];
  /** Replay time in ms. A motion value, so animation follows it without React renders. */
  time: MotionValue<number>;
  /** The event running now. Changes once per event. */
  eventIndex: number;
  playing: boolean;
  setPlaying: (playing: boolean) => void;
  /** Pause and jump to event `i`, at the moment its walk arrives. */
  seek: (i: number) => void;
};

/** Longest step the clock takes in one tick, so one long stall never jumps far ahead. */
const MAX_FRAME_MS = 1500;

/**
 * The replay's clock. It follows wall time while playing, holds still while
 * the tab is hidden and picks up where it was on return.
 * Playing again after the end starts over.
 */
export function useReplayClock(timeline: TimelineEvent[], opts: { autoPlay?: boolean } = {}): ReplayClock {
  const time = useMotionValue(0);
  const [eventIndex, setEventIndex] = useState(0);
  const [playing, setPlayingState] = useState(Boolean(opts.autoPlay));
  const indexRef = useRef(0);
  const end = timeline[timeline.length - 1]?.at ?? 0;

  const jump = useCallback(
    (t: number) => {
      time.set(t);
      const i = eventIndexAt(timeline, t);
      indexRef.current = i;
      setEventIndex(i);
    },
    [time, timeline],
  );

  useEffect(() => {
    if (!playing) return;
    let frame = 0;
    let done = false;
    let last = performance.now();
    // Advance by wall time. Animation frames keep it smooth; a slow interval
    // keeps it moving in a page that gets few frames. A hidden tab holds still.
    const advance = () => {
      const now = performance.now();
      const dt = Math.min(MAX_FRAME_MS, Math.max(0, now - last));
      last = now;
      if (done || document.hidden) return;
      const t = Math.min(end, time.get() + dt);
      time.set(t);
      const i = eventIndexAt(timeline, t);
      if (i !== indexRef.current) {
        indexRef.current = i;
        setEventIndex(i);
      }
      if (t >= end) {
        done = true;
        setPlayingState(false);
      }
    };
    const onFrame = () => {
      advance();
      if (!done) frame = requestAnimationFrame(onFrame);
    };
    const interval = window.setInterval(advance, 250);
    const onVisible = () => {
      last = performance.now();
    };
    document.addEventListener("visibilitychange", onVisible);
    frame = requestAnimationFrame(onFrame);
    return () => {
      cancelAnimationFrame(frame);
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [playing, end, time, timeline]);

  const setPlaying = useCallback(
    (p: boolean) => {
      if (p && time.get() >= end) jump(0);
      setPlayingState(p);
    },
    [end, jump, time],
  );

  const seek = useCallback(
    (i: number) => {
      setPlayingState(false);
      jump(arrivalTime(timeline, i));
    },
    [jump, timeline],
  );

  return { timeline, time, eventIndex, playing, setPlaying, seek };
}
