import type { SceneZone } from "@/lib/scene.gen";
import { ART } from "./art.gen";
import {
  SLAB_H,
  TILE_H,
  TILE_W,
  ZONES,
  isoToScreen,
  itemSize,
  type LabelBox,
  type PlacedItem,
  type Point,
  type TitleBox,
} from "./layout";

// ---------------------------------------------------------------------------
// Isometric geometry helpers (all deterministic, rounded to 0.01 px)

const EX: Point = { x: TILE_W / 2, y: TILE_H / 2 }; // one grid unit along +x
const EY: Point = { x: -TILE_W / 2, y: TILE_H / 2 }; // one grid unit along +y

const r2 = (n: number) => Math.round(n * 100) / 100;
const pts = (ps: Point[]) => ps.map((p) => `${r2(p.x)},${r2(p.y)}`).join(" ");
const add = (p: Point, a: Point, s = 1): Point => ({ x: p.x + a.x * s, y: p.y + a.y * s });
const up = (p: Point, h: number): Point => ({ x: p.x, y: p.y - h });
const mid = (a: Point, b: Point, t = 0.5): Point => ({
  x: a.x + (b.x - a.x) * t,
  y: a.y + (b.y - a.y) * t,
});

type Box = {
  back: Point;
  right: Point;
  front: Point;
  left: Point;
  top: string;
  leftFace: string;
  rightFace: string;
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
    top: pts([up(back, h), up(right, h), up(front, h), up(left, h)]),
    leftFace: pts([left, front, up(front, h), up(left, h)]),
    rightFace: pts([front, right, up(right, h), up(front, h)]),
  };
}

function BoxShape({ box, tone = "item", flagged }: { box: Box; tone?: "item" | "dark"; flagged?: boolean }) {
  const prefix = tone === "dark" ? "--map-dark" : "--map-item";
  return (
    <g stroke={flagged ? "var(--map-flag)" : "var(--map-edge)"} strokeWidth={flagged ? 1.4 : 0.8} strokeLinejoin="round">
      <polygon points={box.leftFace} fill={`var(${prefix}-left)`} />
      <polygon points={box.rightFace} fill={`var(${prefix}-right)`} />
      <polygon points={box.top} fill={`var(${prefix}-top)`} />
    </g>
  );
}

// ---------------------------------------------------------------------------
// Item shapes, one per kind. Footprints and heights come from ITEM_SIZE so
// the label pass knows exactly where each item is.

function ItemShape({ p }: { p: PlacedItem }) {
  const c: Point = { x: p.x, y: p.y };
  const flagged = p.item.flagged;
  const { w, d, h } = itemSize(p.item.kind);
  const edge = flagged ? "var(--map-flag)" : "var(--map-edge)";
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
      const desk = isoBox(c, w, d, 14);
      const lamp = up(mid(desk.back, desk.right, 0.75), 14);
      return (
        <g>
          <BoxShape box={desk} flagged={flagged} />
          <line x1={lamp.x} y1={lamp.y} x2={lamp.x} y2={lamp.y - 10} stroke="var(--map-edge)" strokeWidth={1.2} />
          <circle cx={lamp.x} cy={lamp.y - 11} r={6} fill="var(--map-lamp)" opacity={0.18} />
          <circle cx={lamp.x} cy={lamp.y - 11} r={2.4} fill="var(--map-lamp)" />
        </g>
      );
    }
    case "function": {
      const frame = isoBox(c, w, d, h);
      const a = up(mid(frame.left, frame.front, 0.16), 2);
      const b = up(mid(frame.left, frame.front, 0.84), 2);
      const knob = up(mid(frame.left, frame.front, 0.72), h * 0.45);
      return (
        <g>
          <BoxShape box={frame} tone="dark" flagged={flagged} />
          <polygon
            points={pts([a, b, up(b, h - 6), up(a, h - 6)])}
            fill={flagged ? "var(--map-flag-soft)" : "var(--map-door)"}
            stroke={flagged ? "var(--map-flag)" : "none"}
            strokeWidth={0.8}
          />
          <circle cx={knob.x} cy={knob.y} r={1.6} fill="var(--map-lamp)" />
        </g>
      );
    }
    case "page": {
      const panel = isoBox(c, w, d, h);
      const a = up(mid(panel.left, panel.front, 0.12), 4);
      const b = up(mid(panel.left, panel.front, 0.88), 4);
      return (
        <g>
          <BoxShape box={panel} tone="dark" flagged={flagged} />
          <polygon points={pts([a, b, up(b, h - 7), up(a, h - 7)])} fill="var(--map-glass)" />
          {[13, 9].map((lh) => {
            const s = up(mid(a, b, 0.14), lh);
            const e = up(mid(a, b, lh === 13 ? 0.8 : 0.55), lh);
            return <line key={lh} x1={s.x} y1={s.y} x2={e.x} y2={e.y} stroke="var(--map-glass-line)" strokeWidth={1.4} strokeLinecap="round" />;
          })}
        </g>
      );
    }
    case "env_file": {
      // The doormat by the shop window; the key under it is the classic leak.
      const mat = isoBox(c, w, d, h);
      const a = up(mid(mat.back, mat.left), h);
      const b = up(mid(mat.right, mat.front), h);
      return (
        <g>
          <BoxShape box={mat} tone="dark" flagged={flagged} />
          <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={edge} strokeWidth={0.8} />
        </g>
      );
    }
    case "table": {
      const box = isoBox(c, w, d, h);
      const plate = up(mid(box.left, box.front), h / 2);
      return (
        <g>
          <BoxShape box={box} flagged={flagged} />
          <circle cx={plate.x} cy={plate.y} r={3} fill="var(--map-dark-right)" stroke={edge} strokeWidth={0.8} />
        </g>
      );
    }
    case "bucket": {
      const crate = isoBox(c, w, d, h);
      return (
        <g>
          <BoxShape box={crate} flagged={flagged} />
          {[h / 3, (2 * h) / 3].map((lh) => (
            <g key={lh} stroke={edge} strokeWidth={0.7}>
              <line x1={crate.left.x} y1={crate.left.y - lh} x2={crate.front.x} y2={crate.front.y - lh} />
              <line x1={crate.front.x} y1={crate.front.y - lh} x2={crate.right.x} y2={crate.right.y - lh} />
            </g>
          ))}
        </g>
      );
    }
    case "external_api": {
      const tower = isoBox(c, w, d, h);
      const windows: Point[] = [];
      for (const wh of [10, 18, 26]) {
        for (const t of [0.3, 0.7]) windows.push(up(mid(tower.left, tower.front, t), wh));
      }
      return (
        <g>
          <BoxShape box={tower} tone="dark" flagged={flagged} />
          {windows.map((wp, i) => (
            <rect key={i} x={wp.x - 1.6} y={wp.y - 2.4} width={3.2} height={4.8} fill="var(--map-lamp)" opacity={i % 3 === 1 ? 0.35 : 0.8} />
          ))}
        </g>
      );
    }
    default:
      return <BoxShape box={isoBox(c, w, d, h)} flagged={flagged} />;
  }
}

export function MapItem({
  p,
  highlighted,
  glowId,
  testIds = true,
}: {
  p: PlacedItem;
  highlighted: boolean;
  glowId: string;
  testIds?: boolean;
}) {
  const { item } = p;
  return (
    <g
      data-testid={testIds ? `item-${item.node_id}` : undefined}
      data-flagged={item.flagged ? "true" : "false"}
      data-highlighted={highlighted ? "true" : "false"}
      data-overflow={p.overflow ? "true" : undefined}
    >
      {item.flagged && !p.overflow && (
        <ellipse cx={p.x} cy={p.y} rx={24} ry={12} fill="var(--map-flag)" opacity={0.16} />
      )}
      {highlighted && (
        <ellipse cx={p.x} cy={p.y} rx={28} ry={14} fill="none" stroke="var(--map-ghost)" strokeWidth={2} />
      )}
      <g filter={item.flagged ? `url(#${glowId})` : undefined} opacity={p.overflow ? 0.75 : 1}>
        <ItemShape p={p} />
      </g>
    </g>
  );
}

// ---------------------------------------------------------------------------
// Labels and titles (drawn in the top layer so nothing covers them)

export function ItemLabel({ l, testIds = true }: { l: LabelBox; testIds?: boolean }) {
  const { pill, font } = l;
  return (
    <g data-testid={testIds ? `label-${l.nodeId}` : undefined}>
      <title>{l.full}</title>
      <rect
        x={r2(pill.x)}
        y={r2(pill.y)}
        width={r2(pill.w)}
        height={r2(pill.h)}
        rx={r2(pill.h / 2)}
        fill="var(--map-label-bg)"
        stroke={l.flagged ? "var(--map-flag)" : "var(--map-label-edge)"}
        strokeWidth={Math.max(1, font / 14)}
      />
      <text
        x={r2(pill.x + pill.w / 2)}
        y={r2(pill.y + pill.h / 2)}
        dominantBaseline="central"
        textAnchor="middle"
        fontSize={r2(font)}
        fill={l.flagged ? "var(--map-flag-ink)" : "var(--map-ink)"}
      >
        {l.text}
      </text>
      {l.badge && l.badgeRect && (
        <g data-testid={testIds ? `overflow-${l.zone}` : undefined}>
          <rect
            x={r2(l.badgeRect.x)}
            y={r2(l.badgeRect.y)}
            width={r2(l.badgeRect.w)}
            height={r2(l.badgeRect.h)}
            rx={r2(l.badgeRect.h / 2)}
            fill="var(--map-badge-bg)"
          />
          <text
            x={r2(l.badgeRect.x + l.badgeRect.w / 2)}
            y={r2(l.badgeRect.y + l.badgeRect.h / 2)}
            dominantBaseline="central"
            textAnchor="middle"
            fontSize={r2(font)}
            fontWeight={600}
            fill="var(--map-ink)"
          >
            {l.badge}
          </text>
        </g>
      )}
    </g>
  );
}

export function ZoneTitle({ t, active, highlighted }: { t: TitleBox; active: boolean; highlighted: boolean }) {
  return (
    <text
      data-zone-title={t.zone}
      x={r2(t.x)}
      y={r2(t.y)}
      textAnchor="middle"
      fontSize={r2(t.font)}
      fontWeight={600}
      letterSpacing={0.2}
      opacity={active ? 1 : 0.45}
      fill={highlighted ? "var(--map-ghost)" : "var(--map-zone-ink)"}
      // A halo in the ground colour keeps titles readable where a route crosses them.
      stroke="var(--map-bg)"
      strokeWidth={r2(t.font / 3.5)}
      strokeLinejoin="round"
      paintOrder="stroke"
    >
      {t.text}
    </text>
  );
}

// ---------------------------------------------------------------------------
// Zones

function zoneCorners(id: SceneZone["id"]) {
  const [ox, oy] = ZONES[id].origin;
  const [w, d] = ZONES[id].size;
  return {
    back: isoToScreen(ox, oy),
    right: isoToScreen(ox + w, oy),
    front: isoToScreen(ox + w, oy + d),
    left: isoToScreen(ox, oy + d),
  };
}

function Street() {
  const z = ZONES.street;
  const [ox, oy] = z.origin;
  const [w, d] = z.size;
  const dashes = [];
  for (let gy = oy + 0.6; gy < oy + d - 0.5; gy += 1.5) {
    const a = up(isoToScreen(ox + w / 2, gy), SLAB_H);
    const b = up(isoToScreen(ox + w / 2, gy + 0.7), SLAB_H);
    dashes.push(<line key={gy} x1={r2(a.x)} y1={r2(a.y)} x2={r2(b.x)} y2={r2(b.y)} stroke="var(--map-lane)" strokeWidth={2} strokeLinecap="round" />);
  }
  return <g>{dashes}</g>;
}

export function MapZone({
  zone,
  highlighted,
  children,
  testIds = true,
}: {
  zone: SceneZone;
  highlighted: boolean;
  children?: React.ReactNode;
  testIds?: boolean;
}) {
  const id = zone.id;
  const def = ZONES[id];
  const { back, right, front, left } = zoneCorners(id);
  const center = mid(back, front);
  const slab = isoBox(center, def.size[0], def.size[1], SLAB_H);
  const art = ART[id];
  const isRoad = id === "street";

  return (
    <g
      data-testid={testIds ? `zone-${id}` : undefined}
      data-active={zone.active ? "true" : "false"}
      data-highlighted={highlighted ? "true" : "false"}
      opacity={zone.active ? 1 : 0.3}
    >
      {art ? (
        <image
          href={art}
          x={left.x}
          y={back.y - SLAB_H - def.wall}
          width={right.x - left.x}
          height={front.y - back.y + SLAB_H + def.wall}
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
          {/* Only the back wall: the street-facing (low x) edge stays open. */}
          {def.wall > 0 && (
            <polygon
              points={pts([up(back, SLAB_H), up(right, SLAB_H), up(right, SLAB_H + def.wall), up(back, SLAB_H + def.wall)])}
              fill="var(--map-wall)"
              stroke="var(--map-slab-edge)"
              strokeWidth={1}
            />
          )}
          {isRoad && <Street />}
        </g>
      )}
      {zone.active ? (
        children
      ) : (
        <text
          x={r2(center.x)}
          y={r2(center.y - SLAB_H)}
          textAnchor="middle"
          dominantBaseline="central"
          fontSize={14}
          fill="var(--map-muted)"
        >
          Not used by this app
        </text>
      )}
    </g>
  );
}
