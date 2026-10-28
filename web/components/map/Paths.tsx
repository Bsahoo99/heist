import { partialPath, pathLength, reachedStops, type PathPoint, type Point } from "./layout";

const r2 = (n: number) => Math.round(n * 100) / 100;
const toPoints = (ps: Point[]) => ps.map((p) => `${r2(p.x)},${r2(p.y)}`).join(" ");

/**
 * Lines float above the ground so they read over slabs and crates. The attack
 * line floats higher than the ghost line so a shared stretch shows both.
 */
const LIFTS = { ghost: 2, attack: 9 } as const;
const lift = (ps: Point[], kind: keyof typeof LIFTS): Point[] =>
  ps.map((p) => ({ x: p.x, y: p.y - LIFTS[kind] }));

function Stops({ points, kind }: { points: PathPoint[]; kind: "ghost" | "attack" }) {
  const color = kind === "ghost" ? "var(--map-ghost)" : "var(--map-flag)";
  return (
    <g>
      {points.map((p, i) => (
        <g key={`${p.itemId}-${i}`}>
          {p.count > 1 && (
            <circle cx={r2(p.x)} cy={r2(p.y - LIFTS[kind])} r={8.5} fill="none" stroke={color} strokeWidth={1.2} opacity={0.8} />
          )}
          <circle
            cx={r2(p.x)}
            cy={r2(p.y - LIFTS[kind])}
            r={kind === "ghost" ? 3.5 : 4.5}
            fill={kind === "ghost" ? "var(--map-bg)" : color}
            stroke={color}
            strokeWidth={1.5}
          />
        </g>
      ))}
    </g>
  );
}

/**
 * The ghost path (the legitimate route) as a faint dashed cyan line, and the
 * attack path as a solid red line. `progress` (0..1) draws the attack line up
 * to that fraction of its length.
 */
export function Paths({
  ghost,
  attack,
  progress = 1,
}: {
  ghost?: PathPoint[];
  attack?: PathPoint[];
  progress?: number;
}) {
  let attackLayer = null;
  if (attack) {
    const total = pathLength(attack);
    const drawn = total * Math.max(0, Math.min(1, progress));
    const line = lift(partialPath(attack, progress), "attack");
    const reached = line.length > 0 ? reachedStops(attack, progress) : [];
    const head = line.length > 1 && progress < 1 ? line[line.length - 1] : null;
    attackLayer = (
      <g>
        <polyline
          data-testid="path-attack"
          data-total-length={r2(total)}
          data-drawn-length={r2(drawn)}
          points={toPoints(line)}
          fill="none"
          stroke="var(--map-flag)"
          strokeWidth={3.5}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <Stops points={reached} kind="attack" />
        {head && <circle cx={r2(head.x)} cy={r2(head.y)} r={6} fill="var(--map-flag)" stroke="var(--map-bg)" strokeWidth={2} />}
      </g>
    );
  }

  return (
    <g data-testid="paths" pointerEvents="none">
      {ghost && (
        <g opacity={0.85}>
          <polyline
            data-testid="path-ghost"
            points={toPoints(lift(ghost, "ghost"))}
            fill="none"
            stroke="var(--map-ghost)"
            strokeWidth={2.5}
            strokeDasharray="7 7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <Stops points={ghost} kind="ghost" />
        </g>
      )}
      {attackLayer}
    </g>
  );
}
