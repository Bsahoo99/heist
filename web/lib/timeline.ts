// The replay's script: a pure function from one finding (or none, for a
// clean app) to timed events. The same input always gives the same timeline.
import type { PathStep, Scene, SceneFinding, Zone as ZoneId } from "@/lib/scene.gen";

export type TimelineEvent = {
  /** Start time in ms from the beginning of the replay. For "end", the moment the replay is over. */
  at: number;
  kind: "ghost" | "attack" | "proof" | "lock-held" | "end";
  /** For ghost and attack: the index in that path. For lock-held: the index among the doors tried. */
  stepIndex?: number;
  zone?: ZoneId;
};

/** Base durations in ms, before the whole timeline is scaled to fit. */
export const BASE_MS = { ghost: 1500, attack: 3000, proof: 5000, "lock-held": 2500, end: 1000 } as const;
export const MIN_MS = 20_000;
export const MAX_MS = 30_000;
export const TARGET_MS = 25_000;

/** The doors a clean app's replay tries, in this order (only active ones). */
export const LOCK_ZONES: ZoneId[] = ["guard_desk", "side_doors", "vault", "warehouse"];

/** One stop the step player can show. Step events come first in the timeline, in this order. */
export type ReplayStep = {
  kind: "ghost" | "attack" | "lock-held" | "proof";
  step: PathStep;
  /** Index within its path (or among the doors tried). */
  index: number;
};

/** Plain copy for a clean app's doors. Story uses the heist metaphor; Why and Code stay plain. */
const LOCK_COPY: Record<string, { story: string; why: string; code: string; data: string }> = {
  guard_desk: {
    story: "The attacker tries to slip past the guard desk. The guard checks every pass.",
    why: "Requests that need a user go through Supabase Auth, and no check found a way around it.",
    code: "No finding for Supabase Auth.",
    data: "nothing",
  },
  side_doors: {
    story: "They rattle every side door. Each one asks for a pass before it opens.",
    why: "Every Edge Function checks who is calling before it does any work.",
    code: "No finding for the Edge Functions.",
    data: "nothing",
  },
  vault: {
    story: "They reach the vault and try every box. Each lock holds.",
    why: "Row level security is on for every table, and the policies only return the caller's own rows.",
    code: "No finding for the database tables.",
    data: "nothing",
  },
  warehouse: {
    story: "They try the warehouse doors. The crates stay shut.",
    why: "Storage buckets have access rules, so files are only served to the people allowed to see them.",
    code: "No finding for the storage buckets.",
    data: "nothing",
  },
};

/** Doors whose lock depends on the database rules (tables and storage), untested without them. */
const RULE_ZONES: ZoneId[] = ["vault", "warehouse"];

function activeLockZones(scene: Scene): ZoneId[] {
  return LOCK_ZONES.filter((id) => {
    // Never show a lock holding that Heist could not test.
    if (!scene.meta.has_db_rules && RULE_ZONES.includes(id)) return false;
    const z = scene.zones.find((zone) => zone.id === id);
    return Boolean(z?.active && z.items.length > 0);
  });
}

/** The steps the replay walks through, in timeline order. */
export function replaySteps(finding: SceneFinding | null, scene: Scene): ReplayStep[] {
  if (finding) {
    return [
      ...finding.ghost_path.map((step, index): ReplayStep => ({ kind: "ghost", step, index })),
      ...finding.attack_path.map((step, index): ReplayStep => ({ kind: "attack", step, index })),
    ];
  }
  return activeLockZones(scene).map((zone, index): ReplayStep => {
    const item = scene.zones.find((z) => z.id === zone)!.items[0];
    const copy = LOCK_COPY[zone];
    return {
      kind: "lock-held",
      index,
      step: {
        zone,
        item_id: item.node_id,
        node_id: item.node_id,
        ref: null,
        story: copy.story,
        why: copy.why,
        code: copy.code,
        data: copy.data,
      },
    };
  });
}

/**
 * The player's steps: the path steps, then for a proved finding one more for
 * the proof (shown on the attack's last stop). Player step i is timeline event i.
 */
export function playerSteps(finding: SceneFinding | null, scene: Scene): ReplayStep[] {
  const steps = replaySteps(finding, scene);
  const last = finding?.attack_path.at(-1);
  if (finding?.status !== "proved" || !last) return steps;
  return [...steps, { kind: "proof", step: last, index: 0 }];
}

/**
 * Build the timeline: the ghost (legitimate) route, then the attack, then the
 * proof for proved findings, then the end. With no finding, the attacker
 * tries each active door and every lock holds. Base durations are scaled
 * linearly so the end lands between 20 and 30 seconds (25 when outside).
 */
export function buildTimeline(finding: SceneFinding | null, scene: Scene): TimelineEvent[] {
  const events: (Omit<TimelineEvent, "at"> & { kind: Exclude<TimelineEvent["kind"], "end"> })[] = [];
  for (const s of replaySteps(finding, scene)) {
    if (s.kind !== "proof") events.push({ kind: s.kind, stepIndex: s.index, zone: s.step.zone });
  }
  if (finding?.status === "proved") {
    const last = finding.attack_path.at(-1);
    events.push({ kind: "proof", zone: last?.zone });
  }

  const out: TimelineEvent[] = [];
  let t = 0;
  for (const e of events) {
    out.push({ ...e, at: t });
    t += BASE_MS[e.kind];
  }
  // The end card holds for its own duration; "end" marks the moment it is over.
  t += BASE_MS.end;
  out.push({ kind: "end", at: t });

  const total = t;
  const factor = total >= MIN_MS && total <= MAX_MS ? 1 : TARGET_MS / total;
  return out.map((e) => ({ ...e, at: Math.round(e.at * factor) }));
}

/** How many events at the start of the timeline are steps (ghost, attack, lock-held). */
export function stepEventCount(timeline: TimelineEvent[]): number {
  return timeline.filter((e) => e.kind === "ghost" || e.kind === "attack" || e.kind === "lock-held").length;
}

/** Share of a step's time spent walking to its stop; the rest holds still for reading. */
export const WALK_SHARE = 0.55;

/**
 * When the walk of event `i` arrives at its stop. Stepping to an event lands
 * here, so a paused replay shows the step it names, not the walk towards it.
 */
export function arrivalTime(timeline: TimelineEvent[], i: number): number {
  const k = Math.max(0, Math.min(i, timeline.length - 1));
  const next = timeline[k + 1];
  if (!next) return timeline[k]?.at ?? 0;
  return timeline[k].at + Math.round((next.at - timeline[k].at) * WALK_SHARE);
}

/** The index of the event running at time `t` (the last one that has started). */
export function eventIndexAt(timeline: TimelineEvent[], t: number): number {
  let i = 0;
  while (i + 1 < timeline.length && timeline[i + 1].at <= t) i++;
  return i;
}
