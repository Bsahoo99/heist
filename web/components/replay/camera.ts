// The step camera for narrow screens: a pure function from the step the
// replay is on to the map frame that shows it.
import type { PathStep, Scene, Zone as ZoneId } from "@/lib/scene.gen";
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
