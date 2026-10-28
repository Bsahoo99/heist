// The fixed city block. Every app is drawn on the same hand-placed layout;
// there is no automatic layout algorithm (spec section 7).
//
// Grid units: +x runs to the right and down the screen, +y to the left and
// down. "Back" of the block is the top of the screen (small x + y).
import type { PathStep, Scene, SceneItem, Zone as ZoneId } from "@/lib/scene.gen";

export type { ZoneId };

export const TILE_W = 64;
export const TILE_H = 32;

/** Height in px of every zone's ground slab; items stand on top of it. */
export const SLAB_H = 6;

type Grid = { origin: [number, number]; size: [number, number]; cols: number; rows: number };

export type ZoneDef = {
  origin: [number, number];
  size: [number, number];
  label: string;
  slots: number;
  /** Where the slots sit inside the zone (defaults to the whole zone). */
  slotGrid: Grid;
};

function zone(
  origin: [number, number],
  size: [number, number],
  label: string,
  cols: number,
  rows: number,
  slotArea?: { origin: [number, number]; size: [number, number] },
): ZoneDef {
  const area = slotArea ?? { origin, size };
  return { origin, size, label, slots: cols * rows, slotGrid: { ...area, cols, rows } };
}

/**
 * Reading order, left to right: the street out front (the visitor waits at its
 * left end), then the shop window, the guard desk and the side doors along the
 * front of the block, the vault at the back with the warehouse beside it, and
 * the outside services across the road on the far side of the street.
 */
export const ZONES: Record<ZoneId, ZoneDef> = {
  vault: zone([3, 0], [8, 6], "Vault", 4, 3),
  warehouse: zone([12, 0], [6, 6], "Warehouse", 3, 2),
  shop_window: zone([0, 7], [6, 4], "Shop window", 3, 2),
  guard_desk: zone([7, 7], [4, 4], "Guard desk", 1, 1),
  side_doors: zone([12, 7], [8, 4], "Side doors", 4, 2),
  street: zone([0, 12], [21, 3], "Street", 1, 1, { origin: [0, 12], size: [3, 3] }),
  across_road: zone([12, 16], [8, 3], "Across the road", 4, 1),
};

/** Zones in painting order, back to front. */
export const ZONE_ORDER: ZoneId[] = [
  "vault",
  "warehouse",
  "shop_window",
  "guard_desk",
  "side_doors",
  "street",
  "across_road",
];

export type Point = { x: number; y: number };

/** 2:1 isometric projection of grid coordinates to screen px. */
export function isoToScreen(x: number, y: number): Point {
  return { x: (x - y) * (TILE_W / 2), y: (x + y) * (TILE_H / 2) };
}

/** Grid coordinates of a slot centre. Slots past the end share the last slot. */
export function gridPosition(zoneId: ZoneId, slotIndex: number): [number, number] {
  const z = ZONES[zoneId];
  const s = Math.max(0, Math.min(slotIndex, z.slots - 1));
  const { origin, size, cols, rows } = z.slotGrid;
  const col = s % cols;
  const row = Math.floor(s / cols);
  return [origin[0] + ((col + 0.5) * size[0]) / cols, origin[1] + ((row + 0.5) * size[1]) / rows];
}

/** Screen position (ground plane) of a slot. Overflow items share the last slot. */
export function itemPosition(zoneId: ZoneId, slotIndex: number): Point {
  const [gx, gy] = gridPosition(zoneId, slotIndex);
  return isoToScreen(gx, gy);
}

export type PlacedItem = {
  zone: ZoneId;
  item: SceneItem;
  slot: number;
  /** True for extras stacked behind the last slot. */
  overflow: boolean;
  /** On the item in the last slot: how many extras sit behind it. */
  extra: number;
  /** Ground position on top of the slab. */
  x: number;
  y: number;
};

/** Offset per overflow item, so the stack reads as boxes behind the last one. */
const OVERFLOW_STEP: Point = { x: 0, y: -5 };

/** Place every item of every active zone into its slot, deterministically. */
export function placeItems(scene: Scene): PlacedItem[] {
  const placed: PlacedItem[] = [];
  for (const id of ZONE_ORDER) {
    const zoneData = scene.zones.find((z) => z.id === id);
    if (!zoneData || !zoneData.active) continue;
    const { slots } = ZONES[id];
    const extra = Math.max(0, zoneData.items.length - slots);
    zoneData.items.forEach((item, i) => {
      const overflow = i >= slots;
      const p = itemPosition(id, i);
      const depth = overflow ? i - slots + 1 : 0;
      placed.push({
        zone: id,
        item,
        slot: Math.min(i, slots - 1),
        overflow,
        extra: !overflow && i === slots - 1 ? extra : 0,
        x: p.x + OVERFLOW_STEP.x * depth,
        y: p.y - SLAB_H + OVERFLOW_STEP.y * depth,
      });
    });
  }
  return placed;
}

export type PathPoint = Point & { itemId: string; zone: ZoneId; count: number };

/**
 * Turn path steps into screen points through each step's item, in order.
 * Consecutive steps on the same item stack into one point (no zero-length
 * segment); steps whose item is not on the map are skipped.
 */
export function pathPoints(steps: PathStep[], scene: Scene): PathPoint[] {
  const byId = new Map(placeItems(scene).map((p) => [p.item.node_id, p]));
  const out: PathPoint[] = [];
  for (const s of steps) {
    const p = byId.get(s.item_id);
    if (!p) continue;
    const last = out[out.length - 1];
    if (last && last.itemId === s.item_id) {
      last.count += 1;
      continue;
    }
    out.push({ x: p.x, y: p.y, itemId: s.item_id, zone: p.zone, count: 1 });
  }
  return out;
}

export function pathLength(points: Point[]): number {
  let total = 0;
  for (let i = 1; i < points.length; i++) {
    total += Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y);
  }
  return total;
}

/** The leading part of a polyline covering `fraction` (0..1) of its length. */
export function partialPath(points: Point[], fraction: number): Point[] {
  const f = Math.max(0, Math.min(1, fraction));
  if (points.length < 2 || f === 0) return [];
  if (f === 1) return points.map(({ x, y }) => ({ x, y }));
  let remaining = pathLength(points) * f;
  const out: Point[] = [{ x: points[0].x, y: points[0].y }];
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    const seg = Math.hypot(b.x - a.x, b.y - a.y);
    if (seg >= remaining) {
      const t = seg === 0 ? 0 : remaining / seg;
      out.push({ x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t });
      return out;
    }
    out.push({ x: b.x, y: b.y });
    remaining -= seg;
  }
  return out;
}

/** The stops a line drawn to `fraction` (0..1) of its length has reached. */
export function reachedStops<T extends Point>(points: T[], fraction: number): T[] {
  const limit = pathLength(points) * Math.max(0, Math.min(1, fraction)) + 1e-6;
  const out: T[] = [];
  let acc = 0;
  for (let i = 0; i < points.length; i++) {
    if (i > 0) acc += Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y);
    if (acc > limit) break;
    out.push(points[i]);
  }
  return out;
}

/** Shorten a label to `max` characters, ending with an ellipsis. */
export function truncateLabel(label: string, max: number): string {
  return label.length <= max ? label : `${label.slice(0, max - 1)}…`;
}

/** Screen bounds of the whole block, with room for buildings above and labels below. */
export const VIEWBOX = (() => {
  const xs: number[] = [];
  const ys: number[] = [];
  for (const z of Object.values(ZONES)) {
    const [ox, oy] = z.origin;
    const [w, h] = z.size;
    for (const [gx, gy] of [
      [ox, oy],
      [ox + w, oy],
      [ox, oy + h],
      [ox + w, oy + h],
    ]) {
      const p = isoToScreen(gx, gy);
      xs.push(p.x);
      ys.push(p.y);
    }
  }
  const pad = { left: 24, right: 24, top: 64, bottom: 40 };
  const x = Math.min(...xs) - pad.left;
  const y = Math.min(...ys) - pad.top;
  const width = Math.max(...xs) + pad.right - x;
  const height = Math.max(...ys) + pad.bottom - y;
  return { x, y, width, height };
})();
