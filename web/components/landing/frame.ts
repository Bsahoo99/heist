// The landing map's frame: close on the sample break-in, so its labels read
// at the size of a two-column landing page.
import type { PathStep, Scene } from "@/lib/scene.gen";
import {
  VIEW_PAD,
  bbox,
  boxRect,
  insideView,
  layoutLabels,
  placeItems,
  routePath,
  zoneTitles,
  type Rect,
  type ViewBox,
} from "@/components/map/layout";

/** Map px across at least, so the route keeps some of the block around it. */
export const LANDING_MIN_WIDTH = 820;

/**
 * Frames the route's stops, the visitor, their labels and the titles of the
 * zones it crosses, shaped like `size`. Items the frame would cut are listed
 * in `hidden`, so the map leaves them out instead of drawing half a box.
 */
export function landingFrame(
  scene: Scene,
  steps: PathStep[],
  size: { width: number; height: number },
): ViewBox & { hidden: string[] } {
  const placed = placeItems(scene);
  const ids = new Set(steps.map((s) => s.item_id));
  const zones = new Set(steps.map((s) => s.zone));
  const rects: Rect[] = [
    ...routePath(steps, scene).points.map((p) => ({ x: p.x, y: p.y, w: 0, h: 0 })),
    ...placed.filter((p) => ids.has(p.item.node_id)).map((p) => boxRect(p.item.kind, p)),
    ...layoutLabels(placed).filter((l) => ids.has(l.nodeId)).map((l) => l.rect),
    ...zoneTitles().filter((t) => zones.has(t.zone)).map((t) => t.rect),
  ];
  const fit = bbox(rects, VIEW_PAD);
  const aspect = size.width / size.height;
  const width = Math.max(fit.width, fit.height * aspect, LANDING_MIN_WIDTH);
  const height = width / aspect;
  const vb = {
    x: fit.x + fit.width / 2 - width / 2,
    y: fit.y + fit.height / 2 - height / 2,
    width,
    height,
  };
  const hidden = placed
    .filter((p) => !p.overflow && !insideView(vb, boxRect(p.item.kind, p)))
    .map((p) => p.item.node_id)
    .sort();
  return { ...vb, hidden };
}
