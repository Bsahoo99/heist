"use client";

import { useMemo, type ReactNode } from "react";
import { motion, useReducedMotion, useTransform, type MotionValue } from "motion/react";
import type { Scene, SceneFinding } from "@/lib/scene.gen";
import { CityMap } from "@/components/map/CityMap";
import { boxRect, layoutLabels, partialPath, placeItems, routePath, type Point, type Rect } from "@/components/map/layout";
import { ProofRows } from "@/components/panels/ProofRows";
import { buildTimeline } from "@/lib/timeline";
import { cameraFrame, pickCorner, wideFrame, type Corner } from "./camera";
import { MARKER, makePlan, placeMarkers, replayView, type ReplayView, type Sprite } from "./replayView";
import { handleStepKeys } from "./StepPlayer";
import { useReplayClock, type ReplayClock } from "./useReplayClock";

/** Largest size multiplier for "Lock held" markers on the narrow map, so they stay near their door. */
const PHONE_MARKER_SCALE = 1.4;

/** Nominal size (px) of the wide map box in the normal results layout at 1280x720. */
export const WIDE_BOX = { width: 892, height: 446 };

/** Nominal size (px) of the proof card laid over the wide map. */
const PROOF_CARD = { width: 380, height: 150 };

/** The narrow map box the step camera frames for (px); the frame keeps this aspect ratio. */
export const NARROW_SIZE = { width: 358, height: 300 };

const r2 = (n: number) => Math.round(n * 100) / 100;
const toPoints = (ps: Point[]) => ps.map((p) => `${r2(p.x)},${r2(p.y)}`).join(" ");

function useWalk(time: MotionValue<number>, sprite: Sprite) {
  const { leg, start, walkMs } = sprite;
  const fraction = useTransform(time, (t) => (walkMs <= 0 ? 1 : Math.max(0, Math.min(1, (t - start) / walkMs))));
  const x = useTransform(fraction, (f) => (leg.length > 1 ? (partialPath(leg, f).at(-1) ?? leg[0]).x : (leg[0]?.x ?? 0)));
  const y = useTransform(fraction, (f) => (leg.length > 1 ? (partialPath(leg, f).at(-1) ?? leg[0]).y : (leg[0]?.y ?? 0)));
  const points = useTransform(fraction, (f) => (leg.length > 1 ? toPoints(partialPath(leg, f)) : ""));
  return { fraction, x, y, points };
}

/** A small figure standing at its ground point (0, 0). */
function Figure({ kind, scale }: { kind: Sprite["kind"]; scale: number }) {
  const ghost = kind === "ghost";
  const color = ghost ? "var(--map-ghost)" : "var(--map-flag)";
  return (
    <g transform={`scale(${r2(scale)})`}>
      <ellipse cx={0} cy={0} rx={9} ry={4.5} fill="var(--map-shadow)" />
      {!ghost && <circle cx={0} cy={-13} r={15} fill="var(--map-flag-soft)" />}
      <path
        d="M-6 0 L-6 -14 Q-6 -20 0 -20 Q6 -20 6 -14 L6 0 Z"
        fill={ghost ? "var(--map-bg)" : color}
        stroke={ghost ? color : "var(--map-bg)"}
        strokeWidth={1.6}
      />
      <circle cx={0} cy={-25} r={5} fill={ghost ? "var(--map-bg)" : color} stroke={ghost ? color : "var(--map-bg)"} strokeWidth={1.6} />
    </g>
  );
}

function Walker({
  time,
  sprite,
  scale,
  pulse,
}: {
  time: MotionValue<number>;
  sprite: Sprite;
  scale: number;
  pulse: boolean;
}) {
  const { x, y, points } = useWalk(time, sprite);
  const reduce = useReducedMotion();
  const ghost = sprite.kind === "ghost";
  return (
    <g pointerEvents="none" data-testid="replay-sprite" data-kind={sprite.kind}>
      {sprite.trail && sprite.leg.length > 1 && (
        <motion.polyline
          points={points}
          fill="none"
          stroke={ghost ? "var(--map-ghost)" : "var(--map-flag)"}
          strokeWidth={ghost ? 2.5 : 3.5}
          strokeDasharray={ghost ? "7 7" : undefined}
          strokeLinecap="round"
          strokeLinejoin="round"
          opacity={ghost ? 0.85 : 1}
        />
      )}
      <motion.g style={{ x, y }}>
        {pulse &&
          (reduce ? (
            <circle r={22 * scale} fill="none" stroke="var(--map-flag)" strokeWidth={2} />
          ) : (
            <motion.circle
              r={14 * scale}
              fill="none"
              stroke="var(--map-flag)"
              strokeWidth={2}
              initial={{ scale: 0.6, opacity: 0.9 }}
              animate={{ scale: 2.4, opacity: 0 }}
              transition={{ duration: 1.4, repeat: Infinity, ease: "easeOut" }}
            />
          ))}
        <Figure kind={sprite.kind} scale={scale} />
      </motion.g>
    </g>
  );
}

function LockMarker({
  time,
  at,
  appearAt,
  scale,
  iconOnly,
}: {
  time: MotionValue<number>;
  at: Point;
  appearAt: number | null;
  scale: number;
  /** Just the padlock (a phone's view of every door, too small for the words). */
  iconOnly: boolean;
}) {
  const opacity = useTransform(time, (t) => (appearAt === null || t >= appearAt ? 1 : 0));
  if (iconOnly) {
    const r = 13 * scale;
    return (
      <motion.g style={{ opacity }} data-testid="lock-held" pointerEvents="none">
        <title>Lock held</title>
        <circle cx={r2(at.x)} cy={r2(at.y)} r={r2(r)} fill="var(--map-label-bg)" stroke="var(--map-lamp)" strokeWidth={1.4 * scale} />
        <g transform={`translate(${r2(at.x - 5 * scale)} ${r2(at.y + 1 * scale)}) scale(${r2(scale)})`} stroke="var(--map-lamp)" fill="none" strokeWidth={1.6}>
          <rect x={0} y={-2} width={10} height={8} rx={1.5} fill="var(--map-lamp)" stroke="none" />
          <path d="M2 -2 V-4.5 A3 3 0 0 1 8 -4.5 V-2" />
        </g>
      </motion.g>
    );
  }
  const font = MARKER.font * scale;
  const w = MARKER.w * scale;
  const h = MARKER.h * scale;
  return (
    <motion.g style={{ opacity }} data-testid="lock-held" pointerEvents="none">
      <g transform={`translate(${r2(at.x)} ${r2(at.y - h / 2)})`}>
        <rect x={-w / 2} y={0} width={w} height={h} rx={h / 2} fill="var(--map-label-bg)" stroke="var(--map-lamp)" strokeWidth={1.4} />
        <g transform={`translate(${r2(-w / 2 + 10 * scale)} ${r2(h / 2)}) scale(${r2(scale)})`} fill="none" stroke="var(--map-lamp)" strokeWidth={1.6}>
          <rect x={0} y={-2} width={10} height={8} rx={1.5} fill="var(--map-lamp)" stroke="none" />
          <path d="M2 -2 V-4.5 A3 3 0 0 1 8 -4.5 V-2" />
        </g>
        <text x={r2(-w / 2 + 25 * scale)} y={r2(h / 2 + font * 0.35)} fontSize={font} fill="var(--map-lamp)" fontWeight={600}>
          Lock held
        </text>
      </g>
    </motion.g>
  );
}

function Overlay({
  time,
  view,
  scale,
  focus,
  focusMarkers,
}: {
  time: MotionValue<number>;
  view: ReplayView;
  scale: number;
  focus: boolean;
  /** Marker spots laid out for the narrow map's own labels. */
  focusMarkers: Point[];
}) {
  const markerScale = focus ? Math.min(scale, PHONE_MARKER_SCALE) : scale;
  const iconOnly = focus && view.camera?.mode === "zones";
  return (
    <g data-testid="replay-overlay">
      {view.markers.map((m, i) => (
        <LockMarker
          key={m.zone}
          time={time}
          at={focus && !iconOnly ? (focusMarkers[i] ?? m) : m}
          appearAt={m.appearAt}
          scale={iconOnly ? scale : markerScale}
          iconOnly={iconOnly}
        />
      ))}
      <Walker key={`${view.phase}-${view.sprite.start}`} time={time} sprite={view.sprite} scale={scale} pulse={view.phase === "proof"} />
    </g>
  );
}

const PHASE_TEXT = {
  ghost: "How it should work",
  attack: "How they get in",
  "lock-held": "Testing the locks",
  proof: "The proof",
  end: "",
} as const;

/** The route style as a small key: dashed cyan for the legitimate route, solid red for the attack. */
function PhaseKey({ phase }: { phase: ReplayView["phase"] }) {
  if (phase === "ghost") return <span className="phase-key phase-key-ghost" aria-hidden="true" />;
  if (phase === "lock-held") return <span className="phase-key phase-key-lock" aria-hidden="true" />;
  return <span className="phase-key phase-key-attack" aria-hidden="true" />;
}

/** The map key: which line is which. Shown for findings, beside the phase. */
function Legend() {
  return (
    <ul className="replay-legend" aria-label="Map key">
      <li>
        <span className="phase-key phase-key-ghost" aria-hidden="true" />
        Legitimate route
      </li>
      <li>
        <span className="phase-key phase-key-attack" aria-hidden="true" />
        Attack route
      </li>
    </ul>
  );
}

function Caption({ view, plan, finding }: { view: ReplayView; plan: ReturnType<typeof makePlan>; finding: SceneFinding | null }) {
  const step = plan.steps[view.stepIndex]?.step;
  if (view.phase === "proof" && finding) {
    return (
      <div className="replay-caption" aria-live="polite">
        <div className="replay-caption-row">
          <p className="replay-caption-phase">
            <PhaseKey phase="proof" />
            {PHASE_TEXT.proof}
          </p>
          <Legend />
        </div>
        <p className="replay-caption-story">
          We ran it on a throwaway copy filled with fake people. These rows came back.
        </p>
      </div>
    );
  }
  const last = plan.steps[view.stepIndex]?.kind ?? "attack";
  const phase = view.phase === "end" ? (last === "proof" ? "attack" : last) : view.phase;
  return (
    <div className="replay-caption" aria-live="polite">
      <div className="replay-caption-row">
        <p className="replay-caption-phase">
          <PhaseKey phase={phase} />
          {PHASE_TEXT[phase]}
        </p>
        {finding && <Legend />}
      </div>
      <p className="replay-caption-story">{step?.story ?? ""}</p>
    </div>
  );
}

/** Shown in the caption's place once the replay is over, so it never covers the map. */
function EndCard({ clean, onAgain }: { clean: boolean; onAgain: () => void }): ReactNode {
  return (
    <div className={clean ? "replay-end replay-end-clean" : "replay-end"} role="status">
      <p className="replay-end-title">
        {clean ? "Heist failed. Your app held up against all 7 checks." : "End of replay"}
      </p>
      {clean ? (
        <p className="replay-badge">Heist-tested: 7/7 locks held</p>
      ) : (
        <p className="replay-end-text">Step through each stop with the player, or pick another finding.</p>
      )}
      <button type="button" className="replay-again" onClick={onAgain}>
        Watch again
      </button>
    </div>
  );
}

/**
 * The heist replay: drives the city map from the timeline. The ghost
 * (legitimate) route walks first, then the attacker walks the attack route
 * along the same lines the map draws, then the proof, then an end card. A
 * clean app's replay tries each door and every lock holds.
 *
 * Pass `clock` to share playback with a StepPlayer; without it the replay
 * runs its own clock (auto-playing when `autoPlay`).
 */
export function Replay({
  scene,
  finding,
  autoPlay = false,
  clock: external,
  idPrefix = "replay",
  wideBox = WIDE_BOX,
}: {
  scene: Scene;
  finding: SceneFinding | null;
  autoPlay?: boolean;
  clock?: ReplayClock;
  idPrefix?: string;
  /** Nominal size (px) of the wide map box: the steady wide frame takes its shape. */
  wideBox?: { width: number; height: number };
}) {
  const timeline = useMemo(() => buildTimeline(finding, scene), [finding, scene]);
  const own = useReplayClock(timeline, { autoPlay: external ? false : autoPlay });
  const clock = external ?? own;
  const reduced = Boolean(useReducedMotion());
  const plan = useMemo(() => makePlan(finding, scene), [finding, scene]);
  const view = useMemo(
    () => replayView(plan, clock.timeline, clock.eventIndex, reduced),
    [plan, clock.timeline, clock.eventIndex, reduced],
  );
  // On a phone the narrow map labels only the shown items, larger, so its
  // markers get their own layout; the current door's marker is framed too.
  const { focusFrame, focusMarkers } = useMemo(() => {
    if (!view.camera) return { focusFrame: undefined, focusMarkers: [] as Point[] };
    const opts = { mode: view.camera.mode };
    const first = cameraFrame(scene, view.camera.steps, view.camera.index, NARROW_SIZE, opts);
    if (view.camera.mode !== "zone" || view.markers.length === 0) return { focusFrame: first, focusMarkers: [] };
    const markerScale = Math.min(first.labelScale, PHONE_MARKER_SCALE);
    const ids = view.markers.map((m) => m.itemId);
    const spots = placeMarkers(scene, ids, { only: first.labelIds, labelScale: first.labelScale, markerScale });
    const cur = spots[spots.length - 1];
    const w = MARKER.w * markerScale;
    const h = MARKER.h * markerScale;
    const extra = [{ x: cur.x - w / 2, y: cur.y - h / 2, w, h }];
    const frame = cameraFrame(scene, view.camera.steps, view.camera.index, NARROW_SIZE, { ...opts, extra });
    return { focusFrame: frame, focusMarkers: spots };
  }, [scene, view.camera, view.markers]);
  // Wide screens: one steady frame on the whole finding (or every door).
  const wide = useMemo(() => {
    const extra =
      plan.kind === "clean"
        ? plan.markerAt.map((p) => ({ x: p.x - MARKER.w / 2, y: p.y - MARKER.h / 2, w: MARKER.w, h: MARKER.h }))
        : [];
    return wideFrame(scene, finding, wideBox, { extra });
  }, [scene, finding, plan, wideBox]);
  // Wide screens: lay the proof card over the corner that hides the least of the heist.
  const proofCorner = useMemo((): Corner => {
    if (finding?.status !== "proved") return "bottom-left";
    const placed = placeItems(scene);
    const steps = [...finding.ghost_path, ...finding.attack_path];
    const ids = new Set(steps.map((st) => st.item_id));
    const obstacles: Rect[] = [
      ...[routePath(finding.ghost_path, scene), routePath(finding.attack_path, scene)].flatMap((r) =>
        r.points.map((p) => ({ x: p.x, y: p.y, w: 0, h: 0 })),
      ),
      ...placed.filter((p) => ids.has(p.item.node_id)).map((p) => boxRect(p.item.kind, p)),
      ...layoutLabels(placed).filter((l) => ids.has(l.nodeId)).map((l) => l.rect),
    ];
    const share = { w: PROOF_CARD.width / wideBox.width, h: PROOF_CARD.height / wideBox.height };
    return pickCorner(wide, share, obstacles);
  }, [scene, finding, wide, wideBox]);
  const playerCount = Math.max(1, clock.timeline.length - 1);
  const ended = view.phase === "end" && !clock.playing;

  return (
    <div className="replay" data-phase={view.phase}>
      <div
        className="replay-map"
        role="group"
        tabIndex={0}
        aria-label="Heist replay. Left and Right arrows step, Space plays or pauses."
        onKeyDown={(e) =>
          handleStepKeys(e, {
            index: view.playerIndex,
            count: playerCount,
            playing: clock.playing,
            onIndex: clock.seek,
            onPlayingChange: clock.setPlaying,
          })
        }
      >
        <CityMap
          scene={scene}
          ghost={view.ghost}
          attack={view.attack}
          progress={view.progress}
          highlight={view.highlight}
          idPrefix={idPrefix}
          focusFrame={focusFrame}
          wideFrame={wide}
          overlay={({ labelScale, focus }) => (
            <Overlay time={clock.time} view={view} scale={labelScale} focus={focus} focusMarkers={focusMarkers} />
          )}
        />
        {view.phase === "proof" && finding && (
          <div className="replay-proof" data-testid="replay-proof" data-corner={proofCorner}>
            <ProofRows rows={finding.proof_rows} compact />
          </div>
        )}
      </div>
      {ended ? (
        <EndCard clean={plan.kind === "clean"} onAgain={() => clock.setPlaying(true)} />
      ) : (
        <Caption view={view} plan={plan} finding={finding} />
      )}
    </div>
  );
}
