import type { SceneZone } from "@/lib/scene.gen";
import { ART } from "./art.gen";
import {
  SLAB_H,
  TILE_H,
  TILE_W,
  ZONES,
  isoToScreen,
  truncateLabel,
  type PlacedItem,
  type Point,
  type ZoneId,
} from "./layout";

// ---------------------------------------------------------------------------
// Isometric geometry helpers (all deterministic, rounded to 0.01 px)

const EX: Point = { x: TILE_W / 2, y: TILE_H / 2 }; // one grid unit along +x
const EY: Point = { x: -TILE_W / 2, y: TILE_H / 2 }; // one grid unit along +y

const r2 = (n: number) => Math.round(n * 100) / 100;
const pts = (ps: Point[]) => ps.map((p) => `${r2(p.x)},${r2(p.y)}`).join(" ");
const add = (p: Point, a: Point, s = 1): Point => ({ x: p.x + a.x * s, y: p.y + a.y * s });
const up = (p: Point, h: number): Point => ({ x: p.x, y: p.y - h });

type Box = {
  back: Point;
  right: Point;
  front: Point;
  left: Point;
  top: string;
  leftFace: string;
  rightFace: string;
  h: number;
};

/** A box standing on ground point `c`, `w` grid units along x, `d` along y, `h` px tall. */
function isoBox(c: Point, w: number, d: number, h: number): Box {
  const back = add(add(c, EX, -w / 2), EY, -d / 2);
  const right = add(add(c, EX, w / 2), EY, -d / 2);
  const front = add(add(c, EX, w / 2), EY, d / 2);
  const left = add(add(c, EX, -w / 2), EY, d / 2);
  return {
    back,
    right,
    front,
    left,
    h,
    top: pts([up(back, h), up(right, h), up(front, h), up(left, h)]),
    leftFace: pts([left, front, up(front, h), up(left, h)]),
    rightFace: pts([front, right, up(right, h), up(front, h)]),
  };
}

const mid = (a: Point, b: Point, t = 0.5): Point => ({
  x: a.x + (b.x - a.x) * t,
  y: a.y + (b.y - a.y) * t,
});

function BoxShape({ box, tone = "item", flagged }: { box: Box; tone?: "item" | "dark"; flagged?: boolean }) {
  const edge = flagged ? "var(--map-flag)" : "var(--map-edge)";
  const prefix = tone === "dark" ? "--map-dark" : "--map-item";
  return (
    <g stroke={edge} strokeWidth={flagged ? 1.4 : 0.8} strokeLinejoin="round">
      <polygon points={box.leftFace} fill={`var(${prefix}-left)`} />
      <polygon points={box.rightFace} fill={`var(${prefix}-right)`} />
      <polygon points={box.top} fill={`var(${prefix}-top)`} />
    </g>
  );
}

// ---------------------------------------------------------------------------
// Item shapes, one per kind

function ItemShape({ p }: { p: PlacedItem }) {
  const c: Point = { x: p.x, y: p.y };
  const flagged = p.item.flagged;
  switch (p.item.kind) {
    case "visitor":
      return (
        <g>
          <ellipse cx={c.x} cy={c.y} rx={11} ry={5.5} fill="var(--map-shadow)" />
          <rect x={c.x - 6.5} y={c.y - 27} width={13} height={22} rx={6.5} fill="var(--map-person)" />
          <circle cx={c.x} cy={c.y - 33} r={6} fill="var(--map-person)" />
        </g>
      );
    case "auth": {
      const desk = isoBox(c, 2, 1, 14);
      const lamp = up(mid(desk.back, desk.right, 0.75), 14);
      return (
        <g>
          <BoxShape box={desk} flagged={flagged} />
          <line x1={lamp.x} y1={lamp.y} x2={lamp.x} y2={lamp.y - 12} stroke="var(--map-edge)" strokeWidth={1.2} />
          <circle cx={lamp.x} cy={lamp.y - 13} r={7} fill="var(--map-lamp)" opacity={0.18} />
          <circle cx={lamp.x} cy={lamp.y - 13} r={2.6} fill="var(--map-lamp)" />
        </g>
      );
    }
    case "function": {
      const frame = isoBox(c, 1.1, 0.24, 34);
      // Door panel inset on the front-left face.
      const a = up(mid(frame.left, frame.front, 0.16), 2);
      const b = up(mid(frame.left, frame.front, 0.84), 2);
      const knob = up(mid(frame.left, frame.front, 0.72), 16);
      return (
        <g>
          <BoxShape box={frame} tone="dark" flagged={flagged} />
          <polygon
            points={pts([a, b, up(b, 28), up(a, 28)])}
            fill={flagged ? "var(--map-flag-soft)" : "var(--map-door)"}
            stroke={flagged ? "var(--map-flag)" : "none"}
            strokeWidth={0.8}
          />
          <circle cx={knob.x} cy={knob.y} r={1.6} fill="var(--map-lamp)" />
        </g>
      );
    }
    case "page": {
      const panel = isoBox(c, 1.2, 0.22, 26);
      const a = up(mid(panel.left, panel.front, 0.12), 4);
      const b = up(mid(panel.left, panel.front, 0.88), 4);
      return (
        <g>
          <BoxShape box={panel} tone="dark" flagged={flagged} />
          <polygon points={pts([a, b, up(b, 19), up(a, 19)])} fill="var(--map-glass)" />
          {[13, 9].map((h) => {
            const s = up(mid(a, b, 0.14), h);
            const e = up(mid(a, b, h === 13 ? 0.8 : 0.55), h);
            return <line key={h} x1={s.x} y1={s.y} x2={e.x} y2={e.y} stroke="var(--map-glass-line)" strokeWidth={1.4} strokeLinecap="round" />;
          })}
        </g>
      );
    }
    case "env_file": {
      // The doormat by the shop window; the key under it is the classic leak.
      const mat = isoBox(c, 1.3, 0.9, 3);
      return (
        <g>
          <BoxShape box={mat} tone="dark" flagged={flagged} />
          <line
            x1={mid(mat.back, mat.left).x}
            y1={mid(mat.back, mat.left).y - 3}
            x2={mid(mat.right, mat.front).x}
            y2={mid(mat.right, mat.front).y - 3}
            stroke="var(--map-edge)"
            strokeWidth={0.8}
          />
        </g>
      );
    }
    case "table": {
      const box = isoBox(c, 1.15, 1.15, 20);
      const plate = up(mid(box.left, box.front), 10);
      return (
        <g>
          <BoxShape box={box} flagged={flagged} />
          <circle cx={plate.x} cy={plate.y} r={3.2} fill="var(--map-dark-right)" stroke={flagged ? "var(--map-flag)" : "var(--map-edge)"} strokeWidth={0.8} />
        </g>
      );
    }
    case "bucket": {
      const crate = isoBox(c, 1.3, 1.3, 22);
      return (
        <g>
          <BoxShape box={crate} flagged={flagged} />
          {[7.5, 14.5].map((h) => (
            <g key={h} stroke={flagged ? "var(--map-flag)" : "var(--map-edge)"} strokeWidth={0.7}>
              <line x1={crate.left.x} y1={crate.left.y - h} x2={crate.front.x} y2={crate.front.y - h} />
              <line x1={crate.front.x} y1={crate.front.y - h} x2={crate.right.x} y2={crate.right.y - h} />
            </g>
          ))}
        </g>
      );
    }
    case "external_api": {
      const tower = isoBox(c, 1.1, 1.1, 46);
      const windows: Point[] = [];
      for (const h of [14, 24, 34]) {
        for (const t of [0.3, 0.7]) windows.push(up(mid(tower.left, tower.front, t), h));
      }
      const tip = up(tower.back, 46);
      return (
        <g>
          <BoxShape box={tower} tone="dark" flagged={flagged} />
          {windows.map((w, i) => (
            <rect key={i} x={w.x - 1.6} y={w.y - 2.4} width={3.2} height={4.8} fill="var(--map-lamp)" opacity={i % 3 === 1 ? 0.35 : 0.8} />
          ))}
          <line x1={tip.x} y1={tip.y + 12} x2={tip.x} y2={tip.y - 2} stroke="var(--map-edge)" strokeWidth={1} />
        </g>
      );
    }
    default:
      return <BoxShape box={isoBox(c, 1, 1, 16)} flagged={flagged} />;
  }
}

export function MapItem({
  p,
  highlighted,
  glowId,
}: {
  p: PlacedItem;
  highlighted: boolean;
  glowId: string;
}) {
  const { item } = p;
  return (
    <g
      data-testid={`item-${item.node_id}`}
      data-flagged={item.flagged ? "true" : "false"}
      data-highlighted={highlighted ? "true" : "false"}
      data-overflow={p.overflow ? "true" : undefined}
    >
      {item.flagged && !p.overflow && (
        <ellipse cx={p.x} cy={p.y} rx={26} ry={13} fill="var(--map-flag)" opacity={0.16} />
      )}
      {highlighted && (
        <ellipse cx={p.x} cy={p.y} rx={30} ry={15} fill="none" stroke="var(--map-ghost)" strokeWidth={2} />
      )}
      <g filter={item.flagged ? `url(#${glowId})` : undefined} opacity={p.overflow ? 0.75 : 1}>
        <ItemShape p={p} />
      </g>
    </g>
  );
}

// ---------------------------------------------------------------------------
// Labels (drawn in a top layer so nothing covers them)

export const LABEL_MAX = 14;
const LABEL_FONT = 12;
const charW = LABEL_FONT * 0.58;

export function ItemLabel({ p }: { p: PlacedItem }) {
  const { item } = p;
  const text = truncateLabel(item.label, LABEL_MAX);
  const w = Math.ceil(text.length * charW) + 14;
  const h = LABEL_FONT + 8;
  const badge = p.extra > 0 ? `+${p.extra}` : null;
  const badgeW = badge ? Math.ceil(badge.length * charW) + 12 : 0;
  return (
    <g transform={`translate(${r2(p.x)} ${r2(p.y + 10)})`}>
      <g className="citymap-label" data-testid={`label-${item.node_id}`}>
        <title>{item.label}</title>
        <rect
          x={-w / 2}
          y={0}
          width={w}
          height={h}
          rx={h / 2}
          fill="var(--map-label-bg)"
          stroke={item.flagged ? "var(--map-flag)" : "var(--map-label-edge)"}
          strokeWidth={1}
        />
        <text
          x={0}
          y={h / 2}
          dominantBaseline="central"
          textAnchor="middle"
          fontSize={LABEL_FONT}
          fill={item.flagged ? "var(--map-flag-ink)" : "var(--map-ink)"}
        >
          {text}
        </text>
        {badge && (
          <g data-testid={`overflow-${p.zone}`}>
            <rect x={w / 2 + 4} y={0} width={badgeW} height={h} rx={h / 2} fill="var(--map-badge-bg)" />
            <text
              x={w / 2 + 4 + badgeW / 2}
              y={h / 2}
              dominantBaseline="central"
              textAnchor="middle"
              fontSize={LABEL_FONT}
              fontWeight={600}
              fill="var(--map-ink)"
            >
              {badge}
            </text>
          </g>
        )}
      </g>
    </g>
  );
}

// ---------------------------------------------------------------------------
// Zones

/** Zones that read as rooms get low back walls; open ground does not. */
const WALL_H: Partial<Record<ZoneId, number>> = {
  vault: 30,
  warehouse: 22,
  shop_window: 16,
  guard_desk: 12,
  side_doors: 16,
};

function zoneCorners(id: ZoneId) {
  const [ox, oy] = ZONES[id].origin;
  const [w, d] = ZONES[id].size;
  return {
    back: isoToScreen(ox, oy),
    right: isoToScreen(ox + w, oy),
    front: isoToScreen(ox + w, oy + d),
    left: isoToScreen(ox, oy + d),
  };
}

/** Where the zone's name sits: just above its back corner. */
export function zoneLabelAnchor(id: ZoneId): Point {
  const { back, left } = zoneCorners(id);
  if (id === "street") return { x: left.x + 18, y: left.y + 22 };
  if (id === "across_road") {
    // Its back corner sits on the street, so name it along the front-left edge.
    const { front } = zoneCorners(id);
    const m = mid(left, front);
    return { x: m.x, y: m.y + 26 };
  }
  return { x: back.x, y: back.y - SLAB_H - (WALL_H[id] ?? 0) - 12 };
}

function Street() {
  const z = ZONES.street;
  const [ox, oy] = z.origin;
  const [w, d] = z.size;
  const dashes = [];
  for (let gx = ox + 1; gx < ox + w - 0.5; gx += 1.5) {
    const a = up(isoToScreen(gx, oy + d / 2), SLAB_H);
    const b = up(isoToScreen(gx + 0.7, oy + d / 2), SLAB_H);
    dashes.push(<line key={gx} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="var(--map-lane)" strokeWidth={2} strokeLinecap="round" />);
  }
  return <g>{dashes}</g>;
}

export function MapZone({
  zone,
  highlighted,
  children,
}: {
  zone: SceneZone;
  highlighted: boolean;
  children?: React.ReactNode;
}) {
  const id = zone.id;
  const def = ZONES[id];
  const { back, right, front, left } = zoneCorners(id);
  const center = mid(back, front);
  const slab = isoBox(center, def.size[0], def.size[1], SLAB_H);
  const wallH = WALL_H[id] ?? 0;
  const art = ART[id];
  const isRoad = id === "street";
  const labelAt = zoneLabelAnchor(id);

  return (
    <g
      data-testid={`zone-${id}`}
      data-active={zone.active ? "true" : "false"}
      data-highlighted={highlighted ? "true" : "false"}
      opacity={zone.active ? 1 : 0.3}
    >
      {art ? (
        <image
          href={art}
          x={left.x}
          y={back.y - SLAB_H - wallH}
          width={right.x - left.x}
          height={front.y - back.y + SLAB_H + wallH}
          preserveAspectRatio="xMidYMax meet"
        />
      ) : (
        <g strokeLinejoin="round">
          <polygon points={slab.leftFace} fill={isRoad ? "var(--map-road-left)" : "var(--map-slab-left)"} />
          <polygon points={slab.rightFace} fill={isRoad ? "var(--map-road-right)" : "var(--map-slab-right)"} />
          <polygon
            points={slab.top}
            fill={isRoad ? "var(--map-road)" : "var(--map-slab-top)"}
            stroke={highlighted ? "var(--map-ghost)" : "var(--map-slab-edge)"}
            strokeWidth={highlighted ? 1.6 : 1}
          />
          {wallH > 0 && (
            <g fill="var(--map-wall)" stroke="var(--map-slab-edge)" strokeWidth={1}>
              <polygon points={pts([up(left, SLAB_H), up(back, SLAB_H), up(back, SLAB_H + wallH), up(left, SLAB_H + wallH)])} />
              <polygon points={pts([up(back, SLAB_H), up(right, SLAB_H), up(right, SLAB_H + wallH), up(back, SLAB_H + wallH)])} />
            </g>
          )}
          {isRoad && <Street />}
        </g>
      )}
      {zone.active ? children : (
        <text
          x={center.x}
          y={center.y - SLAB_H}
          textAnchor="middle"
          dominantBaseline="central"
          fontSize={13}
          fill="var(--map-muted)"
        >
          Not used by this app
        </text>
      )}
      <text
        className="citymap-zone-label"
        x={labelAt.x}
        y={labelAt.y}
        textAnchor={id === "street" ? "start" : "middle"}
        fontSize={14}
        fontWeight={600}
        letterSpacing={0.2}
        fill={highlighted ? "var(--map-ghost)" : "var(--map-zone-ink)"}
      >
        {def.label}
      </text>
    </g>
  );
}
