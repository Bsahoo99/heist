// The step camera for narrow screens: a pure function from the step the
// replay is on to the map frame that shows it.
import type { PathStep, Scene, SceneFinding, Zone as ZoneId } from "@/lib/scene.gen";
import { LOCK_ZONES } from "@/lib/timeline";
import {
  VIEW_PAD,
  bbox,
  boxRect,
  layoutLabels,
  narrowLabelScale,
  placeItems,
  routePath,
  zoneRects,
  zoneTitles,
  type Rect,
  type ViewBox,
} from "@/components/map/layout";

/** Never zoom in further than this many map px across, so a single item keeps its context. */
export const CAMERA_MIN_WIDTH = 560;

export type CameraMode = "neighbours" | "zone" | "zones";

export type CameraFrame = {
  viewBox: ViewBox;
  labelScale: number;
  /** The items to label: the step and its neighbours. */
  labelIds: Set<string>;
  /** The zones whose titles to show. */
  titleZones: Set<ZoneId>;
};

/** Grow a box around its centre to `aspect` (width / height) and at least `minWidth` wide. */
function fit(vb: ViewBox, aspect: number, minWidth: number): ViewBox {
  let width = Math.max(vb.width, minWidth, vb.height * aspect);
  let height = width / aspect;
  if (height < vb.height) {
    height = vb.height;
    width = height * aspect;
  }
  const cx = vb.x + vb.width / 2;
  const cy = vb.y + vb.height / 2;
  const r = (n: number) => Math.round(n * 100) / 100;
  return { x: r(cx - width / 2), y: r(cy - height / 2), width: r(width), height: r(height) };
}

/**
 * The frame for step `index` of `steps` on a `size` px container.
 *
 * - "neighbours" (default): step `index` and its neighbours (index - 1 and
 *   index + 1), the route legs between them and their labels, plus the street
 *   and the visitor on step 0.
 * - "zone": the whole zone of step `index` with its title (a clean app's
 *   replay, which tests one door at a time).
 * - "zones": every zone the steps visit, with their titles (a clean app's end).
 *
 * `extra`: more map rects the frame must hold (the replay's markers).
 *
 * The frame always has the container's aspect ratio, so the map keeps its
 * height while the camera moves.
 */
export function cameraFrame(
  scene: Scene,
  steps: PathStep[],
  index: number,
  size: { width: number; height: number },
  opts: { mode?: CameraMode; extra?: Rect[] } = {},
): CameraFrame {
  const aspect = size.width / size.height;
  const placed = placeItems(scene);
  const byId = new Map(placed.map((p) => [p.item.node_id, p]));
  const i = Math.max(0, Math.min(index, steps.length - 1));
  const step = steps[i];

  if (!step) {
    const labelScale = narrowLabelScale(CAMERA_MIN_WIDTH);
    const vb = fit(bbox(zoneRects("street"), VIEW_PAD), aspect, CAMERA_MIN_WIDTH);
    return { viewBox: vb, labelScale, labelIds: new Set(), titleZones: new Set(["street"]) };
  }

  const extra = opts.extra ?? [];
  if (opts.mode === "zone" || opts.mode === "zones") {
    const zones = new Set<ZoneId>(opts.mode === "zone" ? [step.zone] : steps.map((s) => s.zone));
    const items = placed.filter((p) => zones.has(p.zone));
    const base: Rect[] = [
      ...[...zones].flatMap((z) => zoneRects(z)),
      ...items.map((p) => boxRect(p.item.kind, p)),
      ...extra,
    ];
    const first = fit(bbox(base, VIEW_PAD), aspect, CAMERA_MIN_WIDTH);
    const labelScale = narrowLabelScale(first.width);
    // The whole-route view of every door is too small for item labels on a phone.
    const labelIds = new Set(opts.mode === "zone" ? items.map((p) => p.item.node_id) : []);
    const labels = layoutLabels(placed, { only: labelIds, scale: labelScale }).map((l) => l.rect);
    const title = zoneTitles(labelScale).filter((t) => zones.has(t.zone)).map((t) => t.rect);
    const viewBox = fit(bbox([...base, ...labels, ...title], VIEW_PAD), aspect, CAMERA_MIN_WIDTH);
    return { viewBox, labelScale, labelIds, titleZones: zones };
  }

  const lo = Math.max(0, i - 1);
  const hi = Math.min(steps.length - 1, i + 1);
  const near = steps.slice(lo, hi + 1);
  const route = routePath(near, scene);
  const base: Rect[] = [...route.points.map((p) => ({ x: p.x, y: p.y, w: 0, h: 0 })), ...extra];
  const labelIds = new Set<string>();
  for (const s of near) {
    const p = byId.get(s.item_id);
    if (!p) continue;
    base.push(boxRect(p.item.kind, p));
    labelIds.add(s.item_id);
  }
  const titleZones = new Set<ZoneId>(near.map((s) => s.zone));
  if (i === 0) {
    base.push(...zoneRects("street"));
    for (const p of placed) if (p.item.kind === "visitor") base.push(boxRect(p.item.kind, p));
    titleZones.add("street");
  }
  const first = fit(bbox(base, VIEW_PAD), aspect, CAMERA_MIN_WIDTH);
  const labelScale = narrowLabelScale(first.width);
  const labels = layoutLabels(placed, { only: labelIds, scale: labelScale }).map((l) => l.rect);
  const titles = zoneTitles(labelScale)
    .filter((t) => titleZones.has(t.zone))
    .map((t) => t.rect);
  const viewBox = fit(bbox([...base, ...labels, ...titles], VIEW_PAD), aspect, CAMERA_MIN_WIDTH);
  return { viewBox, labelScale, labelIds, titleZones };
}

/** Wide screens never zoom in further than this many map px across. */
export const WIDE_MIN_WIDTH = 900;

/**
 * The wide-screen frame: one steady frame for the whole replay (no per-step
 * camera, so a recording does not sway). It holds the finding's ghost and
 * attack routes, their items and labels, the titles of the zones they visit,
 * and the street with the visitor. With no finding (a clean app), it holds
 * the active doors from the guard desk to the warehouse. `extra`: more map
 * rects to hold (the clean app's "Lock held" markers).
 */
export function wideFrame(
  scene: Scene,
  finding: SceneFinding | null,
  size: { width: number; height: number },
  opts: { extra?: Rect[] } = {},
): ViewBox {
  const aspect = size.width / size.height;
  const placed = placeItems(scene);
  const labels = layoutLabels(placed);
  const titles = zoneTitles();
  const rects: Rect[] = [...(opts.extra ?? [])];
  let zones: Set<ZoneId>;
  let ids: Set<string>;
  if (finding) {
    const steps = [...finding.ghost_path, ...finding.attack_path];
    ids = new Set(steps.map((s) => s.item_id));
    zones = new Set<ZoneId>([...steps.map((s) => s.zone), "street"]);
    for (const r of [routePath(finding.ghost_path, scene), routePath(finding.attack_path, scene)]) {
      rects.push(...r.points.map((p) => ({ x: p.x, y: p.y, w: 0, h: 0 })));
    }
    rects.push(...zoneRects("street"));
    for (const p of placed) if (p.item.kind === "visitor") ids.add(p.item.node_id);
  } else {
    zones = new Set(
      LOCK_ZONES.filter((id) => scene.zones.find((z) => z.id === id)?.active),
    );
    ids = new Set(placed.filter((p) => zones.has(p.zone)).map((p) => p.item.node_id));
    for (const z of zones) rects.push(...zoneRects(z));
  }
  for (const p of placed) if (ids.has(p.item.node_id)) rects.push(boxRect(p.item.kind, p));
  rects.push(...labels.filter((l) => ids.has(l.nodeId)).map((l) => l.rect));
  rects.push(...titles.filter((t) => zones.has(t.zone)).map((t) => t.rect));
  return fit(bbox(rects, VIEW_PAD), aspect, WIDE_MIN_WIDTH);
}

export type Corner = "bottom-left" | "top-right" | "top-left" | "bottom-right";
const CORNERS: Corner[] = ["bottom-left", "top-right", "top-left", "bottom-right"];

/** A card's area in map units: `card` is its size as a share of the frame, inset by 2%. */
export function cornerRect(frame: ViewBox, card: { w: number; h: number }, corner: Corner): Rect {
  const w = frame.width * card.w;
  const h = frame.height * card.h;
  const inset = { x: frame.width * 0.02, y: frame.height * 0.03 };
  const left = corner.endsWith("left");
  const top = corner.startsWith("top");
  return {
    x: left ? frame.x + inset.x : frame.x + frame.width - inset.x - w,
    y: top ? frame.y + inset.y : frame.y + frame.height - inset.y - h,
    w,
    h,
  };
}

/**
 * Where a card laid over the map hides the least: the first corner (bottom
 * left, top right, top left, bottom right) that covers none of `obstacles`,
 * else the one covering the fewest. Deterministic.
 */
export function pickCorner(frame: ViewBox, card: { w: number; h: number }, obstacles: Rect[]): Corner {
  let best: Corner = CORNERS[0];
  let bestHits = Infinity;
  for (const c of CORNERS) {
    const r = cornerRect(frame, card, c);
    const hits = obstacles.filter(
      (o) => o.x < r.x + r.w && r.x < o.x + Math.max(o.w, 0.01) && o.y < r.y + r.h && r.y < o.y + Math.max(o.h, 0.01),
    ).length;
    if (hits === 0) return c;
    if (hits < bestHits) {
      bestHits = hits;
      best = c;
    }
  }
  return best;
}
