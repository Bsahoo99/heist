import type { PathStep, Scene, Zone as ZoneId } from "@/lib/scene.gen";
import { ZONES, ZONE_ORDER, VIEWBOX, isoToScreen, pathPoints, placeItems } from "./layout";
import { Paths } from "./Paths";
import { ItemLabel, MapItem, MapZone } from "./Zone";

export type CityMapProps = {
  scene: Scene;
  highlight?: { nodeId?: string; zone?: ZoneId };
  ghost?: PathStep[];
  attack?: PathStep[];
  /** 0..1: how much of the attack line is drawn, by length. Defaults to 1. */
  progress?: number;
  className?: string;
  /** Prefix for SVG ids; set a different one when two maps share a page. */
  idPrefix?: string;
};

function summary(scene: Scene, flagged: number): string {
  const active = ZONE_ORDER.filter((id) => scene.zones.find((z) => z.id === id)?.active).map(
    (id) => ZONES[id].label,
  );
  const zones = active.length ? `Active zones: ${active.join(", ")}.` : "No active zones.";
  const flags = `${flagged} flagged ${flagged === 1 ? "item" : "items"}.`;
  return `City map of ${scene.meta.repo}. ${zones} ${flags}`;
}

/** Faint tile grid under the whole block. */
function GroundGrid() {
  const minX = -1;
  const maxX = 22;
  const minY = -1;
  const maxY = 20;
  const lines = [];
  for (let gx = minX; gx <= maxX; gx++) {
    const a = isoToScreen(gx, minY);
    const b = isoToScreen(gx, maxY);
    lines.push(<line key={`x${gx}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />);
  }
  for (let gy = minY; gy <= maxY; gy++) {
    const a = isoToScreen(minX, gy);
    const b = isoToScreen(maxX, gy);
    lines.push(<line key={`y${gy}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />);
  }
  return (
    <g stroke="var(--map-grid)" strokeWidth={1}>
      {lines}
    </g>
  );
}

/**
 * The fixed isometric city block, filled in with one Scene's parts.
 * Rendering is a pure function of the props: the same Scene always gives the
 * same SVG.
 */
export function CityMap({
  scene,
  highlight,
  ghost,
  attack,
  progress = 1,
  className,
  idPrefix = "citymap",
}: CityMapProps) {
  // Fixed ids (not useId) so the same Scene always gives byte-identical SVG.
  const glowId = `${idPrefix}-glow`;
  const clipId = `${idPrefix}-clip`;
  const placed = placeItems(scene);
  const flaggedCount = placed.filter((p) => p.item.flagged).length;
  const ghostPts = ghost ? pathPoints(ghost, scene) : undefined;
  const attackPts = attack ? pathPoints(attack, scene) : undefined;
  const vb = VIEWBOX;

  return (
    <div className={`citymap ${className ?? ""}`}>
      <div className="citymap-pan">
        <div className="citymap-center" aria-hidden="true" />
        <svg
          role="img"
          aria-label={summary(scene, flaggedCount)}
          viewBox={`${vb.x} ${vb.y} ${vb.width} ${vb.height}`}
          preserveAspectRatio="xMidYMid meet"
          className="citymap-svg"
          fontFamily="var(--font-sans), system-ui, sans-serif"
        >
          <title>{`City map of ${scene.meta.repo}`}</title>
          <defs>
            <filter id={glowId} x="-60%" y="-60%" width="220%" height="220%">
              <feDropShadow dx={0} dy={0} stdDeviation={3.5} style={{ floodColor: "var(--map-flag)" }} floodOpacity={0.75} />
            </filter>
            <clipPath id={clipId}>
              <rect x={vb.x} y={vb.y} width={vb.width} height={vb.height} />
            </clipPath>
          </defs>
          <g clipPath={`url(#${clipId})`}>
            <GroundGrid />
          </g>
          {ZONE_ORDER.map((id) => {
            const zone = scene.zones.find((z) => z.id === id) ?? { id, active: false, items: [] };
            return (
              <MapZone key={id} zone={zone} highlighted={highlight?.zone === id}>
                {placed
                  .filter((p) => p.zone === id)
                  // Paint back to front: overflow extras first, then by depth.
                  .map((p, i) => ({ p, i }))
                  .sort((a, b) => b.p.y - a.p.y === 0 ? a.i - b.i : a.p.y - b.p.y)
                  .map(({ p }) => (
                    <MapItem
                      key={p.item.node_id}
                      p={p}
                      glowId={glowId}
                      highlighted={highlight?.nodeId === p.item.node_id}
                    />
                  ))}
              </MapZone>
            );
          })}
          <Paths ghost={ghostPts} attack={attackPts} progress={progress} />
          <g data-testid="labels">
            {placed
              .filter((p) => !p.overflow)
              .map((p) => (
                <ItemLabel key={p.item.node_id} p={p} />
              ))}
          </g>
        </svg>
      </div>
    </div>
  );
}
