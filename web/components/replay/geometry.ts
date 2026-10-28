// Replay geometry on top of the map's own routes (components/map/layout.ts):
// which stop each step lands on, and the stretch of the drawn line between
// two stops, so the walking sprite follows exactly the line Paths draws.
import type { PathStep, Scene } from "@/lib/scene.gen";
import { cumulativeLengths, offsetPolyline, pathStops, type Point, type Route } from "@/components/map/layout";

/**
 * For each step, the index of the route stop it lands on. Repeated steps on
 * one item share a stop; a step whose item is not on the map keeps the
 * previous stop (-1 before the first).
 */
export function stepStopIndices(steps: PathStep[], scene: Scene): number[] {
  return steps.map((_, k) => pathStops(steps.slice(0, k + 1), scene).length - 1);
}

/** The drawn (offset) line from stop `from` to stop `to`. */
export function legPoints(route: Route, offset: number, from: number, to: number): Point[] {
  const line = offsetPolyline(route.points, offset);
  const a = route.stops[Math.max(0, from)]?.index ?? 0;
  const b = route.stops[Math.max(0, to)]?.index ?? a;
  return line.slice(Math.min(a, b), Math.max(a, b) + 1);
}

/** The share (0..1) of the drawn line's length up to stop `stop`. */
export function stopFraction(route: Route, offset: number, stop: number): number {
  if (stop < 0 || route.stops.length === 0) return 0;
  const cum = cumulativeLengths(offsetPolyline(route.points, offset));
  const total = cum[cum.length - 1] ?? 0;
  if (total === 0) return stop >= 0 ? 1 : 0;
  const s = route.stops[Math.min(stop, route.stops.length - 1)];
  return Math.min(1, cum[s.index] / total);
}
