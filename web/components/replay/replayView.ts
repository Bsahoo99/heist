// What the replay shows at each event: a pure function of the finding, the
// timeline and the event index. Replay.tsx only renders it.
import type { PathStep, Scene, SceneFinding, Zone as ZoneId } from "@/lib/scene.gen";
import {
  boxRect,
  layoutLabels,
  offsetPolyline,
  placeItems,
  routePath,
  zoneTitles,
  type Point,
  type Rect,
  type Route,
} from "@/components/map/layout";
import { PATH_OFFSET } from "@/components/map/Paths";
import { WALK_SHARE, replaySteps, stepEventCount, type ReplayStep, type TimelineEvent } from "@/lib/timeline";
import type { CameraMode } from "./camera";
import { legPoints, stepStopIndices, stopFraction } from "./geometry";

type FindingPlan = {
  kind: "finding";
  finding: SceneFinding;
  steps: ReplayStep[];
  ghostRoute: Route;
  ghostStops: number[];
  attackRoute: Route;
  attackStops: number[];
};

type CleanPlan = {
  kind: "clean";
  steps: ReplayStep[];
  /** The attacker's walk: from the visitor to each door in turn. */
  walkRoute: Route;
  walkStops: number[];
  /** Index in the walk of the first door (1 when the walk starts at the visitor). */
  first: number;
  /** The centre of each door's "Lock held" marker: near the item tried, clear of everything else. */
  markerAt: Point[];
};

export type ReplayPlan = FindingPlan | CleanPlan;

export function makePlan(finding: SceneFinding | null, scene: Scene): ReplayPlan {
  const steps = replaySteps(finding, scene);
  if (finding) {
    return {
      kind: "finding",
      finding,
      steps,
      ghostRoute: routePath(finding.ghost_path, scene),
      ghostStops: stepStopIndices(finding.ghost_path, scene),
      attackRoute: routePath(finding.attack_path, scene),
      attackStops: stepStopIndices(finding.attack_path, scene),
    };
  }
  const visitor = scene.zones.find((z) => z.id === "street" && z.active)?.items[0];
  const origin: PathStep[] = visitor
    ? [{ zone: "street", item_id: visitor.node_id, node_id: visitor.node_id, ref: null, story: "", why: "", code: "", data: "" }]
    : [];
  const walk = [...origin, ...steps.map((s) => s.step)];
  const markerAt = placeMarkers(scene, steps.map((s) => s.step.item_id));
  return {
    kind: "clean",
    steps,
    walkRoute: routePath(walk, scene),
    walkStops: stepStopIndices(walk, scene),
    first: origin.length,
    markerAt,
  };
}

/** Size of a "Lock held" marker at scale 1 (map px). */
export const MARKER = { font: 13, w: 101, h: 23 };

const overlaps = (a: Rect, b: Rect) =>
  a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

/**
 * Place a "Lock held" marker for each item: above it if that is free, else
 * the nearest free spot around it, clear of every item box, item label, zone
 * title and earlier marker. Deterministic.
 *
 * By default this is the full map's layout. A narrow map labels fewer items
 * at a larger size: pass the labels it shows (`only`), their `labelScale`
 * and the size the markers are drawn at (`markerScale`).
 */
export function placeMarkers(
  scene: Scene,
  itemIds: string[],
  opts: { only?: Set<string>; labelScale?: number; markerScale?: number } = {},
): Point[] {
  const labelScale = opts.labelScale ?? 1;
  const k = opts.markerScale ?? 1;
  const placed = placeItems(scene);
  const taken: Rect[] = [
    ...placed.filter((p) => !p.overflow).map((p) => boxRect(p.item.kind, p)),
    ...layoutLabels(placed, { only: opts.only, scale: labelScale }).map((l) => l.rect),
    ...zoneTitles(labelScale).map((t) => t.rect),
  ];
  const w = MARKER.w * k;
  const h = MARKER.h * k;
  return itemIds.map((id) => {
    const p = placed.find((q) => q.item.node_id === id);
    if (!p) return { x: 0, y: 0 };
    const box = boxRect(p.item.kind, p);
    const cx = p.x;
    const top = box.y - 6 * k - h / 2;
    let best: Point = { x: cx, y: top };
    search: for (let ring = 0; ring <= 12; ring++) {
      for (let dy = 0; dy <= ring; dy++) {
        for (let dx = -ring; dx <= ring; dx++) {
          if (Math.max(Math.abs(dx), dy) !== ring) continue;
          const c = { x: cx + dx * 12 * k, y: top - dy * 10 * k };
          const r = { x: c.x - w / 2, y: c.y - h / 2, w, h };
          if (!taken.some((t) => overlaps(t, r))) {
            best = c;
            break search;
          }
        }
      }
    }
    taken.push({ x: best.x - w / 2, y: best.y - h / 2, w, h });
    return best;
  });
}

export type Sprite = {
  kind: "ghost" | "attack";
  /** Whether the walk leaves a line behind it (not for a clean app's tries). */
  trail: boolean;
  /** The drawn line to walk along. One point: standing still. */
  leg: Point[];
  /** Replay time (ms) the walk starts, and how long it takes. */
  start: number;
  walkMs: number;
};

export type ReplayView = {
  phase: TimelineEvent["kind"];
  /** The step the player and panel show. */
  stepIndex: number;
  ghost?: PathStep[];
  attack?: PathStep[];
  /** How much of the attack line CityMap draws (the current leg is drawn by the sprite). */
  progress: number;
  sprite: Sprite;
  highlight?: { nodeId?: string; zone?: ZoneId };
  /** Clean app: "Lock held" markers. `appearAt` is the replay time it shows up, or null when already shown. */
  markers: { zone: ZoneId; itemId: string; x: number; y: number; appearAt: number | null }[];
  /** The narrow-screen camera target. */
  camera: { steps: PathStep[]; index: number; mode: CameraMode } | null;
};

function stopPoint(route: Route, offset: number, stop: number): Point[] {
  if (route.points.length === 0) return [];
  const line = offsetPolyline(route.points, offset);
  const s = route.stops[Math.max(0, stop)];
  return s ? [line[s.index]] : [line[0]];
}

/** The leg from the previous step's stop to this one's, or just this stop when there is nothing to walk. */
function walkLeg(route: Route, offset: number, stops: number[], k: number, reduced: boolean): Point[] {
  const to = stops[k];
  const from = k > 0 ? stops[k - 1] : -1;
  if (reduced || from < 0 || to < 0 || from === to) return stopPoint(route, offset, Math.max(to, 0));
  return legPoints(route, offset, from, to);
}

export function replayView(
  plan: ReplayPlan,
  timeline: TimelineEvent[],
  eventIndex: number,
  reduced: boolean,
): ReplayView {
  const i = Math.max(0, Math.min(eventIndex, timeline.length - 1));
  const ev = timeline[i];
  const next = timeline[i + 1];
  const walkMs = next ? Math.round((next.at - ev.at) * WALK_SHARE) : 0;
  const stepIndex = Math.min(i, stepEventCount(timeline) - 1);
  const current = plan.steps[Math.max(0, stepIndex)]?.step;
  const highlight = current ? { nodeId: current.item_id, zone: current.zone } : undefined;

  if (plan.kind === "clean") {
    const k = ev.kind === "lock-held" ? (ev.stepIndex ?? 0) : plan.steps.length - 1;
    const walking = ev.kind === "lock-held";
    const w = plan.first + k;
    const leg = walking
      ? walkLeg(plan.walkRoute, 0, plan.walkStops, w, reduced)
      : stopPoint(plan.walkRoute, 0, plan.walkStops[w] ?? 0);
    const shown = walking ? k + 1 : plan.steps.length;
    const markers = plan.steps.slice(0, shown).map((s, j) => ({
      zone: s.step.zone,
      itemId: s.step.item_id,
      ...plan.markerAt[j],
      appearAt: walking && j === k && !reduced && leg.length > 1 ? ev.at + walkMs : null,
    }));
    return {
      phase: ev.kind,
      stepIndex,
      progress: 0,
      sprite: { kind: "attack", trail: false, leg, start: ev.at, walkMs: leg.length > 1 ? walkMs : 0 },
      highlight: walking ? highlight : undefined,
      markers,
      camera: { steps: plan.steps.map((s) => s.step), index: k, mode: walking ? "zone" : "zones" },
    };
  }

  const { finding } = plan;
  const G = PATH_OFFSET.ghost;
  const A = PATH_OFFSET.attack;

  if (ev.kind === "ghost") {
    const k = ev.stepIndex ?? 0;
    const shown = finding.ghost_path.slice(0, reduced ? k + 1 : k);
    const leg = walkLeg(plan.ghostRoute, G, plan.ghostStops, k, reduced);
    return {
      phase: "ghost",
      stepIndex,
      ghost: shown.length ? shown : undefined,
      progress: 0,
      sprite: { kind: "ghost", trail: true, leg, start: ev.at, walkMs: leg.length > 1 ? walkMs : 0 },
      highlight,
      markers: [],
      camera: { steps: finding.ghost_path, index: k, mode: "neighbours" },
    };
  }

  if (ev.kind === "attack") {
    const k = ev.stepIndex ?? 0;
    const drawnTo = reduced ? plan.attackStops[k] : k > 0 ? plan.attackStops[k - 1] : -1;
    const leg = walkLeg(plan.attackRoute, A, plan.attackStops, k, reduced);
    return {
      phase: "attack",
      stepIndex,
      ghost: finding.ghost_path,
      attack: finding.attack_path,
      progress: drawnTo < 0 ? 0 : stopFraction(plan.attackRoute, A, drawnTo),
      sprite: { kind: "attack", trail: true, leg, start: ev.at, walkMs: leg.length > 1 ? walkMs : 0 },
      highlight,
      markers: [],
      camera: { steps: finding.attack_path, index: k, mode: "neighbours" },
    };
  }

  // Proof and end: the whole attack drawn, the attacker standing at the last stop.
  const last = finding.attack_path.length - 1;
  return {
    phase: ev.kind,
    stepIndex,
    ghost: finding.ghost_path,
    attack: finding.attack_path,
    progress: 1,
    sprite: { kind: "attack", trail: true, leg: stopPoint(plan.attackRoute, A, plan.attackStops[last] ?? 0), start: ev.at, walkMs: 0 },
    highlight,
    markers: [],
    camera: { steps: finding.attack_path, index: Math.max(0, last), mode: "neighbours" },
  };
}
