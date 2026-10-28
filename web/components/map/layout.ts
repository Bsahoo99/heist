// The fixed city block. Every app is drawn on the same hand-placed layout;
// there is no automatic layout algorithm (spec section 7).
//
// Grid units: +x runs to the right and down the screen, +y to the left and
// down. Every function here is pure: the same Scene always gives the same
// geometry.
import type { PathStep, Scene, SceneItem, Zone as ZoneId } from "@/lib/scene.gen";

export type { ZoneId };

export const TILE_W = 64;
export const TILE_H = 32;

/** Height in px of every zone's ground slab; items stand on top of it. */
export const SLAB_H = 6;

export type Point = { x: number; y: number };
export type Rect = { x: number; y: number; w: number; h: number };

type Grid = { origin: [number, number]; size: [number, number]; cols: number; rows: number };

export type ZoneDef = {
  origin: [number, number];
  size: [number, number];
  label: string;
  slots: number;
  /** Where the slots sit inside the zone (defaults to the whole zone). Columns run along x, rows along y. */
  slotGrid: Grid;
  /** Height in px of the wall along the zone's back (y = origin) edge. */
  wall: number;
  /** The item kind the zone is sized for. */
  kind: string;
};

function zone(
  origin: [number, number],
  size: [number, number],
  label: string,
  cols: number,
  rows: number,
  wall: number,
  kind: string,
  slotArea?: { origin: [number, number]; size: [number, number] },
): ZoneDef {
  const area = slotArea ?? { origin, size };
  return { origin, size, label, slots: cols * rows, slotGrid: { ...area, cols, rows }, wall, kind };
}

/**
 * Reading order, left to right on screen: the outside services across the
 * road, the street (running along y on the left edge, the visitor standing
 * in it), then the rooms chained along x: shop window, guard desk, side
 * doors, and the vault with the warehouse beside it. Each room's low-x edge
 * faces the street and is open; that is where routes walk in.
 */
export const ZONES: Record<ZoneId, ZoneDef> = {
  across_road: zone([-8, 0.5], [3.5, 8.5], "Across the road", 2, 2, 0, "external_api", {
    origin: [-8, 1.5],
    size: [3.5, 7.5],
  }),
  street: zone([-4, 0], [3, 10], "Street", 1, 1, 0, "visitor", { origin: [-4, 3], size: [3, 4] }),
  shop_window: zone([0, 1], [5.5, 7.5], "Shop window", 2, 3, 16, "page"),
  guard_desk: zone([6.5, 3], [3, 4], "Guard desk", 1, 1, 12, "auth", { origin: [6.5, 3.5], size: [3, 4] }),
  side_doors: zone([10.5, 0], [5, 10], "Side doors", 2, 4, 16, "function"),
  vault: zone([16.5, -2], [10, 8], "Vault", 4, 3, 26, "table"),
  warehouse: zone([16.5, 7], [10, 5], "Warehouse", 3, 2, 20, "bucket"),
};

/** Zones in painting order, back to front (by the depth of their front corner). */
export const ZONE_ORDER: ZoneId[] = [
  "across_road",
  "street",
  "shop_window",
  "guard_desk",
  "side_doors",
  "vault",
  "warehouse",
];

/** 2:1 isometric projection of grid coordinates to screen px. */
export function isoToScreen(x: number, y: number): Point {
  return { x: (x - y) * (TILE_W / 2), y: (x + y) * (TILE_H / 2) };
}

/**
 * Cells in fill order: a checkerboard, so a zone up to half full has no two
 * items side by side and their labels hang clear of the neighbouring boxes.
 */
function fillOrder(cols: number, rows: number): [number, number][] {
  const even: [number, number][] = [];
  const odd: [number, number][] = [];
  for (let row = 0; row < rows; row++) {
    for (let col = 0; col < cols; col++) ((row + col) % 2 === 0 ? even : odd).push([col, row]);
  }
  return [...even, ...odd];
}

/** Grid coordinates of a slot centre. Slots past the end share the last slot. */
export function gridPosition(zoneId: ZoneId, slotIndex: number): [number, number] {
  const z = ZONES[zoneId];
  const s = Math.max(0, Math.min(slotIndex, z.slots - 1));
  const { origin, size, cols, rows } = z.slotGrid;
  const [col, row] = fillOrder(cols, rows)[s];
  return [origin[0] + ((col + 0.5) * size[0]) / cols, origin[1] + ((row + 0.5) * size[1]) / rows];
}

/** Screen position (ground plane) of a slot. Overflow items share the last slot. */
export function itemPosition(zoneId: ZoneId, slotIndex: number): Point {
  const [gx, gy] = gridPosition(zoneId, slotIndex);
  return isoToScreen(gx, gy);
}

// ---------------------------------------------------------------------------
// Items

/** Footprint (grid units along x and y) and height (px) of each item kind. */
export const ITEM_SIZE: Record<string, { w: number; d: number; h: number }> = {
  visitor: { w: 0.7, d: 0.7, h: 40 },
  auth: { w: 2, d: 1, h: 30 },
  function: { w: 1.1, d: 0.24, h: 28 },
  page: { w: 1.2, d: 0.22, h: 26 },
  env_file: { w: 1.3, d: 0.9, h: 3 },
  table: { w: 0.85, d: 0.85, h: 17 },
  bucket: { w: 1.2, d: 1.2, h: 20 },
  external_api: { w: 1, d: 1, h: 32 },
};
const DEFAULT_SIZE = { w: 1, d: 1, h: 16 };
export const itemSize = (kind: string) => ITEM_SIZE[kind] ?? DEFAULT_SIZE;

/** Screen bounding box of an item standing on ground point `p`. */
export function boxRect(kind: string, p: Point): Rect {
  const { w, d, h } = itemSize(kind);
  const half = (TILE_W / 4) * (w + d); // 16 px per grid unit, each side
  const depth = (TILE_H / 4) * (w + d); // 8 px per grid unit, up and down
  return { x: p.x - half, y: p.y - depth - h, w: 2 * half, h: 2 * depth + h };
}

export type PlacedItem = {
  zone: ZoneId;
  item: SceneItem;
  slot: number;
  /** True for extras stacked behind the last slot. */
  overflow: boolean;
  /** On the item in the last slot: how many extras sit behind it. */
  extra: number;
  /** Grid position of the slot. */
  gx: number;
  gy: number;
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
      const [gx, gy] = gridPosition(id, i);
      const p = isoToScreen(gx, gy);
      const depth = overflow ? i - slots + 1 : 0;
      placed.push({
        zone: id,
        item,
        slot: Math.min(i, slots - 1),
        overflow,
        extra: !overflow && i === slots - 1 ? extra : 0,
        gx,
        gy,
        x: p.x + OVERFLOW_STEP.x * depth,
        y: p.y - SLAB_H + OVERFLOW_STEP.y * depth,
      });
    });
  }
  return placed;
}

// ---------------------------------------------------------------------------
// Labels

export const LABEL_FONT = 14;
export const LABEL_MAX = 16;
/** Zones more than half full use shorter labels so they still fit between boxes. */
export const LABEL_MAX_DENSE = 12;
export const TITLE_FONT = 15;
const CHAR_W = 0.58; // average Geist glyph width, in ems
const LABEL_PAD_X = 16;
const LABEL_PAD_Y = 10;
const LABEL_GAP = 4;

/** Shorten a label to `max` characters, ending with an ellipsis. */
export function truncateLabel(label: string, max: number): string {
  return label.length <= max ? label : `${label.slice(0, max - 1)}…`;
}

export type LabelBox = {
  nodeId: string;
  zone: ZoneId;
  full: string;
  text: string;
  flagged: boolean;
  /** "+N" for the last slot of an overflowing zone. */
  badge: string | null;
  font: number;
  /** The pill (without the badge). */
  pill: Rect;
  /** The "+N" badge beside the pill. */
  badgeRect: Rect | null;
  /** Pill plus badge: the area the label occupies. */
  rect: Rect;
};

export type TitleBox = { zone: ZoneId; text: string; font: number; x: number; y: number; rect: Rect };

const overlaps = (a: Rect, b: Rect) =>
  a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

/**
 * Zone titles sit above the middle of the zone's back edge, clear of the
 * alleys between rooms. The warehouse sits in front of the vault, so its title
 * goes beside its free front-right edge instead.
 */
export function zoneTitles(scale = 1): TitleBox[] {
  const font = TITLE_FONT * scale;
  const titles = ZONE_ORDER.map((id): TitleBox => {
    const z = ZONES[id];
    const [ox, oy] = z.origin;
    const [w, d] = z.size;
    const tw = Math.ceil(z.label.length * font * 0.6);
    const th = font + 4;
    let x: number;
    let y: number; // baseline
    if (id === "warehouse") {
      const edge = isoToScreen(ox + w, oy + d / 2);
      x = edge.x + tw / 2 + 12 * scale;
      y = edge.y + font / 2;
    } else {
      // Across the road, slide right along the back edge to clear the towers.
      const along = id === "across_road" ? 0.8 : 0.5;
      const edge = isoToScreen(ox + w * along, oy);
      x = edge.x;
      y = edge.y - SLAB_H - z.wall - 10 * scale;
    }
    return { zone: id, text: z.label, font, x, y, rect: { x: x - tw / 2, y: y - font, w: tw, h: th } };
  });
  // Enlarged titles (narrow screens) can meet; lift a later one clear of the earlier ones.
  const placedTitles: TitleBox[] = [];
  for (const t of titles) {
    let moved = t;
    for (const k of [0, -1, -2, 1, 2, -3, 3]) {
      const dy = k * (t.rect.h + 2 * scale);
      const cand = { ...t, y: t.y + dy, rect: { ...t.rect, y: t.rect.y + dy } };
      if (!placedTitles.some((o) => overlaps(o.rect, cand.rect))) {
        moved = cand;
        break;
      }
    }
    placedTitles.push(moved);
  }
  return placedTitles;
}

/**
 * Candidate spots, best first: below the item (nudged sideways and further
 * down), then above it. Units: steps of 10 x 8 px at scale 1.
 */
const NUDGES: { dx: number; dy: number; above: boolean }[] = (() => {
  const out: { dx: number; dy: number; above: boolean; cost: number }[] = [];
  for (const above of [false, true]) {
    for (let dy = 0; dy <= 8; dy++) {
      for (let dx = -14; dx <= 14; dx++) {
        out.push({ dx, dy, above, cost: Math.hypot(dx, dy * 1.4) + (above ? 6 : 0) });
      }
    }
  }
  return out.sort((a, b) => a.cost - b.cost).map(({ dx, dy, above }) => ({ dx, dy, above }));
})();

/**
 * Place item labels: each pill is anchored just in front of its item's front
 * corner, then a deterministic greedy pass nudges it until it clears every
 * other item's box, the labels already placed and the zone titles.
 *
 * `only`: show labels just for these node ids. `scale`: label size multiplier.
 */
export function layoutLabels(
  placed: PlacedItem[],
  opts: { only?: Set<string>; scale?: number } = {},
): LabelBox[] {
  const scale = opts.scale ?? 1;
  const font = LABEL_FONT * scale;
  const charW = font * CHAR_W;
  const h = font + LABEL_PAD_Y;
  const visible = placed.filter((p) => !p.overflow);
  const boxes = visible.map((p) => ({ id: p.item.node_id, rect: boxRect(p.item.kind, p) }));
  const taken: Rect[] = zoneTitles(scale).map((t) => t.rect);
  const out: LabelBox[] = [];
  const dense = new Set(
    ZONE_ORDER.filter(
      (id) => ZONES[id].slots >= 4 && visible.filter((p) => p.zone === id).length > ZONES[id].slots / 2,
    ),
  );

  for (const p of visible) {
    if (opts.only && !opts.only.has(p.item.node_id)) continue;
    const text = truncateLabel(p.item.label, dense.has(p.zone) ? LABEL_MAX_DENSE : LABEL_MAX);
    const w = Math.ceil(text.length * charW) + LABEL_PAD_X * scale;
    const badge = p.extra > 0 ? `+${p.extra}` : null;
    const badgeW = badge ? Math.ceil(badge.length * charW) + 12 * scale : 0;
    const totalW = w + (badge ? 4 * scale + badgeW : 0);
    const own = boxRect(p.item.kind, p);
    const below = own.y + own.h + LABEL_GAP * scale;
    const above = own.y - LABEL_GAP * scale - h;
    const others = boxes.filter((b) => b.id !== p.item.node_id).map((b) => b.rect);
    const step = { x: 10 * scale, y: 8 * scale };

    let best: Rect | null = null;
    let bestScore = Infinity;
    for (const n of NUDGES) {
      const y = n.above ? above - n.dy * step.y : below + n.dy * step.y;
      const rect = { x: p.x - w / 2 + n.dx * step.x, y, w: totalW, h };
      const hits = [...others, ...taken].filter((r) => overlaps(rect, r)).length;
      if (hits === 0) {
        best = rect;
        break;
      }
      if (hits < bestScore) {
        bestScore = hits;
        best = rect;
      }
    }
    const rect = best as Rect;
    taken.push(rect);
    out.push({
      nodeId: p.item.node_id,
      zone: p.zone,
      full: p.item.label,
      text,
      flagged: p.item.flagged,
      badge,
      font,
      pill: { x: rect.x, y: rect.y, w, h },
      badgeRect: badge ? { x: rect.x + w + 4 * scale, y: rect.y, w: badgeW, h } : null,
      rect,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Paths

export type Route = {
  /** The polyline, in screen px. Consecutive points are distinct. */
  points: Point[];
  /** One entry per stop: the index of its point and how many steps stacked there. */
  stops: { index: number; itemId: string; count: number }[];
};

type Stop = { itemId: string; zone: ZoneId; gx: number; gy: number; count: number };

/** Path steps to stops on the map. Repeated steps on one item stack; unknown items are skipped. */
export function pathStops(steps: PathStep[], scene: Scene): Stop[] {
  const byId = new Map(placeItems(scene).map((p) => [p.item.node_id, p]));
  const out: Stop[] = [];
  for (const s of steps) {
    const p = byId.get(s.item_id);
    if (!p) continue;
    const last = out[out.length - 1];
    if (last && last.itemId === s.item_id) {
      last.count += 1;
      continue;
    }
    out.push({ itemId: s.item_id, zone: p.zone, gx: p.gx, gy: p.gy, count: 1 });
  }
  return out;
}

const ground = (gx: number, gy: number): Point => {
  const p = isoToScreen(gx, gy);
  return { x: p.x, y: p.y - SLAB_H };
};

const ARC_SAMPLES = 24;

/** A curved "call" from a to b, bulging upwards. */
function arc(a: Point, b: Point): Point[] {
  const dist = Math.hypot(b.x - a.x, b.y - a.y);
  // Keep the curve's highest point at or below `m`, inside the frame: for a
  // quadratic with ends at a.y, b.y that peak is reached when the control
  // point sits at m - sqrt((a.y - m)(b.y - m)).
  const m = VIEWBOX.y + 24;
  const lowest = m - Math.sqrt(Math.max(0, (a.y - m) * (b.y - m)));
  const c = { x: (a.x + b.x) / 2, y: Math.max(Math.min(a.y, b.y) - 0.22 * dist - 24, lowest) };
  const out: Point[] = [];
  for (let i = 1; i <= ARC_SAMPLES; i++) {
    const t = i / ARC_SAMPLES;
    const u = 1 - t;
    out.push({ x: u * u * a.x + 2 * u * t * c.x + t * t * b.x, y: u * u * a.y + 2 * u * t * c.y + t * t * b.y });
  }
  return out;
}

/**
 * Route path steps through the map. Walking legs follow the grid axes as
 * L-shapes: first along y to the target's row, then along x, so a leg moving
 * right enters the next room through its open, street-facing edge. A leg to
 * or from across the road is an outbound call and is drawn as an arc.
 */
export function routePath(steps: PathStep[], scene: Scene): Route {
  const stops = pathStops(steps, scene);
  const points: Point[] = [];
  const out: Route["stops"] = [];
  const push = (p: Point) => {
    const last = points[points.length - 1];
    if (!last || Math.hypot(p.x - last.x, p.y - last.y) > 1e-6) points.push(p);
  };
  stops.forEach((s, i) => {
    if (i === 0) {
      push(ground(s.gx, s.gy));
    } else {
      const a = stops[i - 1];
      if (a.zone === "across_road" || s.zone === "across_road") {
        arc(ground(a.gx, a.gy), ground(s.gx, s.gy)).forEach(push);
      } else {
        push(ground(a.gx, s.gy));
        push(ground(s.gx, s.gy));
      }
    }
    out.push({ index: points.length - 1, itemId: s.itemId, count: s.count });
  });
  return { points, stops: out };
}

/** Shift a polyline sideways by `d` px (positive is to the left of travel), mitring the joints. */
export function offsetPolyline(points: Point[], d: number): Point[] {
  if (points.length < 2 || d === 0) return points.map((p) => ({ ...p }));
  const normals = points.slice(1).map((b, i) => {
    const a = points[i];
    const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
    return { x: (b.y - a.y) / len, y: -(b.x - a.x) / len };
  });
  return points.map((p, i) => {
    const n1 = normals[Math.max(0, i - 1)];
    const n2 = normals[Math.min(normals.length - 1, i)];
    const m = { x: n1.x + n2.x, y: n1.y + n2.y };
    const mLen = Math.hypot(m.x, m.y);
    if (mLen < 1e-6) return { x: p.x + n2.x * d, y: p.y + n2.y * d };
    const cos = (m.x / mLen) * n2.x + (m.y / mLen) * n2.y;
    const k = d / Math.max(cos, 0.35); // limit the mitre on sharp turns
    return { x: p.x + (m.x / mLen) * k, y: p.y + (m.y / mLen) * k };
  });
}

export function pathLength(points: Point[]): number {
  let total = 0;
  for (let i = 1; i < points.length; i++) {
    total += Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y);
  }
  return total;
}

/** Length along the polyline at each point. */
export function cumulativeLengths(points: Point[]): number[] {
  const out = [0];
  for (let i = 1; i < points.length; i++) {
    out.push(out[i - 1] + Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y));
  }
  return out;
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

// ---------------------------------------------------------------------------
// Framing

export type ViewBox = { x: number; y: number; width: number; height: number };

function bbox(rects: Rect[], pad: number): ViewBox {
  const x0 = Math.min(...rects.map((r) => r.x)) - pad;
  const y0 = Math.min(...rects.map((r) => r.y)) - pad;
  const x1 = Math.max(...rects.map((r) => r.x + r.w)) + pad;
  const y1 = Math.max(...rects.map((r) => r.y + r.h)) + pad;
  return { x: Math.floor(x0), y: Math.floor(y0), width: Math.ceil(x1 - x0), height: Math.ceil(y1 - y0) };
}

const pointRect = (p: Point): Rect => ({ x: p.x, y: p.y, w: 0, h: 0 });

function zoneRects(id: ZoneId): Rect[] {
  const z = ZONES[id];
  const [ox, oy] = z.origin;
  const [w, d] = z.size;
  const corners = [isoToScreen(ox, oy), isoToScreen(ox + w, oy), isoToScreen(ox, oy + d), isoToScreen(ox + w, oy + d)];
  return [...corners.map(pointRect), ...corners.map((c) => pointRect({ x: c.x, y: c.y - SLAB_H - z.wall }))];
}

export const VIEW_PAD = 16;

/**
 * The whole block's frame: every zone with its walls and title, plus every
 * slot with the tallest item its zone is drawn for and a full-width label
 * below it.
 */
export const VIEWBOX: ViewBox = (() => {
  const rects: Rect[] = [];
  const font = LABEL_FONT;
  const labelW = Math.ceil(LABEL_MAX * font * CHAR_W) + LABEL_PAD_X;
  for (const id of ZONE_ORDER) {
    const z = ZONES[id];
    rects.push(...zoneRects(id));
    for (let s = 0; s < z.slots; s++) {
      const g = gridPosition(id, s);
      const p = ground(g[0], g[1]);
      const box = boxRect(z.kind, p);
      rects.push(box);
      rects.push({ x: p.x - labelW / 2, y: box.y + box.h + LABEL_GAP, w: labelW, h: font + LABEL_PAD_Y });
    }
  }
  rects.push(...zoneTitles().map((t) => t.rect));
  return bbox(rects, VIEW_PAD);
})();

/** Narrow screens: label size multiplier so labels render at about 11 px on a 358 px wide map. */
export function narrowLabelScale(viewWidth: number): number {
  return Math.max(1, (11 * viewWidth) / 358 / LABEL_FONT);
}

/** The node ids a focused (narrow) map labels: items on the paths, and flagged items. */
export function focusLabelIds(scene: Scene, ghost: PathStep[] = [], attack: PathStep[] = []): Set<string> {
  const ids = new Set([...ghost, ...attack].map((s) => s.item_id));
  for (const p of placeItems(scene)) if (p.item.flagged) ids.add(p.item.node_id);
  return ids;
}

/**
 * The frame for a narrow screen: the finding's ghost and attack routes, their
 * labels, the street and the visitor, with padding. With no paths, the whole
 * block.
 */
export function focusViewBox(
  scene: Scene,
  ghost: PathStep[] = [],
  attack: PathStep[] = [],
): { viewBox: ViewBox; labelScale: number } {
  const routes = [routePath(ghost, scene), routePath(attack, scene)];
  const pts = routes.flatMap((r) => r.points);
  if (pts.length === 0) {
    // No finding: the whole block, grown to hold the enlarged titles.
    const labelScale = narrowLabelScale(VIEWBOX.width);
    const whole: Rect = { x: VIEWBOX.x, y: VIEWBOX.y, w: VIEWBOX.width, h: VIEWBOX.height };
    return { viewBox: bbox([whole, ...zoneTitles(labelScale).map((t) => t.rect)], 0), labelScale };
  }
  const placed = placeItems(scene);
  const base: Rect[] = [...pts.map(pointRect), ...zoneRects("street")];
  for (const p of placed) if (p.item.kind === "visitor") base.push(boxRect(p.item.kind, p));
  const first = bbox(base, VIEW_PAD);
  const labelScale = narrowLabelScale(first.width);
  const pathIds = new Set([...ghost, ...attack].map((s) => s.item_id));
  const labels = layoutLabels(placed, { only: focusLabelIds(scene, ghost, attack), scale: labelScale });
  const onPath = labels.filter((l) => pathIds.has(l.nodeId)).map((l) => l.rect);
  const boxes = placed.filter((p) => pathIds.has(p.item.node_id)).map((p) => boxRect(p.item.kind, p));
  const pathZones = new Set<ZoneId>([...ghost, ...attack].map((s) => s.zone));
  pathZones.add("street");
  const titles = zoneTitles(labelScale)
    .filter((t) => pathZones.has(t.zone))
    .map((t) => t.rect);
  return { viewBox: bbox([...base, ...onPath, ...boxes, ...titles], VIEW_PAD), labelScale };
}

/** Whether a rect lies wholly inside a view box. */
export function insideView(vb: ViewBox, r: Rect): boolean {
  return r.x >= vb.x && r.y >= vb.y && r.x + r.w <= vb.x + vb.width && r.y + r.h <= vb.y + vb.height;
}
