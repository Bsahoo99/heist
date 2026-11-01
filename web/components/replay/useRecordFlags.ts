"use client";

import { useEffect } from "react";
import { arrivalTime, BASE_MS, type TimelineEvent } from "@/lib/timeline";
import type { ReplayClock } from "./useReplayClock";

/** How long the end card holds in a recording before the replay counts as done: its timeline duration. */
export const END_HOLD_MS = BASE_MS.end;

/** The replay's peak: the walk to its last stop has arrived (the proof card, the attack's end, the last lock). */
export function climaxTime(timeline: TimelineEvent[]): number {
  return arrivalTime(timeline, Math.max(0, timeline.length - 2));
}

/**
 * Record mode's flags on `document.body.dataset`, for `pnpm export`:
 * `started` on the first replay frame (the export trims everything before
 * it), `climax` once the replay reaches its peak (the poster frame), and
 * `done` once the end card has held for `END_HOLD_MS`.
 */
export function useRecordFlags(clock: ReplayClock, ended: boolean, enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    const flags = document.body.dataset;
    const frame = requestAnimationFrame(() => {
      flags.started = "true";
    });
    return () => {
      cancelAnimationFrame(frame);
      delete flags.started;
      delete flags.climax;
      delete flags.done;
    };
  }, [enabled]);

  const { time, timeline } = clock;
  useEffect(() => {
    if (!enabled) return;
    const at = climaxTime(timeline);
    const check = (t: number) => {
      if (t >= at) document.body.dataset.climax = "true";
    };
    check(time.get());
    return time.on("change", check);
  }, [enabled, time, timeline]);

  useEffect(() => {
    if (!enabled || !ended) return;
    const timer = window.setTimeout(() => {
      document.body.dataset.done = "true";
    }, END_HOLD_MS);
    return () => window.clearTimeout(timer);
  }, [enabled, ended]);
}
