import { cumulativeLengths, offsetPolyline, partialPath, type Point, type Route } from "./layout";

const r2 = (n: number) => Math.round(n * 100) / 100;
const toPoints = (ps: Point[]) => ps.map((p) => `${r2(p.x)},${r2(p.y)}`).join(" ");

/**
 * The two lines sit on opposite sides of their route, offset perpendicular to
 * each segment, so a ghost and an attack over the same items both stay visible.
 */
export const PATH_OFFSET = { ghost: 4, attack: -4 } as const;

function Stops({
  points,
  stops,
  kind,
  testIds,
}: {
  points: Point[];
  stops: Route["stops"];
  kind: "ghost" | "attack";
  testIds: boolean;
}) {
  const color = kind === "ghost" ? "var(--map-ghost)" : "var(--map-flag)";
  return (
    <g>
      {stops.map((s, i) => {
        const p = points[s.index];
        return (
          <g key={`${s.itemId}-${i}`} data-testid={testIds ? `stop-${kind}` : undefined} data-count={s.count}>
            {s.count > 1 && (
              <circle cx={r2(p.x)} cy={r2(p.y)} r={8.5} fill="none" stroke={color} strokeWidth={1.2} opacity={0.8} />
            )}
            <circle
              cx={r2(p.x)}
              cy={r2(p.y)}
              r={kind === "ghost" ? 3.5 : 4.5}
              fill={kind === "ghost" ? "var(--map-bg)" : color}
              stroke={color}
              strokeWidth={1.5}
            />
          </g>
        );
      })}
    </g>
  );
}

/**
 * The ghost route (the legitimate path) as a faint dashed cyan line, and the
 * attack route as a solid red line. `progress` (0..1) draws the attack line
 * up to that fraction of its real length.
 */
export function Paths({
  ghost,
  attack,
  progress = 1,
  testIds = true,
}: {
  ghost?: Route;
  attack?: Route;
  progress?: number;
  testIds?: boolean;
}) {
  let attackLayer = null;
  if (attack) {
    const full = offsetPolyline(attack.points, PATH_OFFSET.attack);
    const cum = cumulativeLengths(full);
    const total = cum[cum.length - 1] ?? 0;
    const f = Math.max(0, Math.min(1, progress));
    const drawn = total * f;
    const line = partialPath(full, f);
    const reached = line.length > 0 ? attack.stops.filter((s) => cum[s.index] <= drawn + 1e-6) : [];
    const head = line.length > 1 && f < 1 ? line[line.length - 1] : null;
    attackLayer = (
      <g>
        <polyline
          data-testid={testIds ? "path-attack" : undefined}
          data-total-length={r2(total)}
          data-drawn-length={r2(drawn)}
          points={toPoints(line)}
          fill="none"
          stroke="var(--map-flag)"
          strokeWidth={3.5}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <Stops points={full} stops={reached} kind="attack" testIds={testIds} />
        {head && <circle cx={r2(head.x)} cy={r2(head.y)} r={6} fill="var(--map-flag)" stroke="var(--map-bg)" strokeWidth={2} />}
      </g>
    );
  }

  let ghostLayer = null;
  if (ghost) {
    const line = offsetPolyline(ghost.points, PATH_OFFSET.ghost);
    ghostLayer = (
      <g opacity={0.85}>
        <polyline
          data-testid={testIds ? "path-ghost" : undefined}
          points={toPoints(line)}
          fill="none"
          stroke="var(--map-ghost)"
          strokeWidth={2.5}
          strokeDasharray="7 7"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <Stops points={line} stops={ghost.stops} kind="ghost" testIds={testIds} />
      </g>
    );
  }

  return (
    <g data-testid={testIds ? "paths" : undefined} pointerEvents="none">
      {ghostLayer}
      {attackLayer}
    </g>
  );
}
