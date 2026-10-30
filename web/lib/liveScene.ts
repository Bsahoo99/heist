// The map while an analysis runs, built from the progress events so far.
import type { ProgressEvent } from "./api";
import type { Scene, SceneItem, Zone as ZoneId } from "./scene.gen";

/** Zones in the engine's Scene order. */
const SCENE_ZONES: ZoneId[] = [
  "street",
  "shop_window",
  "guard_desk",
  "side_doors",
  "vault",
  "warehouse",
  "across_road",
];

/** Node kinds that never get their own box on the map (as in the engine's Scene). */
const HIDDEN_KINDS = new Set(["policy", "client_call"]);
const ZONE_IDS = new Set<string>(SCENE_ZONES);

const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

/**
 * A Scene with no findings: a zone lights up once a `node_found` event puts a
 * visible item in it. Items are sorted by node id, like the engine's Scene,
 * so each one lands on the slot it keeps when the results arrive. `repo`
 * only names the map for screen readers.
 */
export function liveScene(events: ProgressEvent[], repo = ""): Scene {
  const byZone = new Map<ZoneId, Map<string, SceneItem>>(SCENE_ZONES.map((z) => [z, new Map()]));
  for (const e of events) {
    if (e.kind !== "node_found") continue;
    const zone = str(e.data.zone);
    const nodeId = str(e.data.node_id);
    const label = str(e.data.label);
    const kind = str(e.data.kind) ?? "page";
    if (!zone || !ZONE_IDS.has(zone) || !nodeId || !label || HIDDEN_KINDS.has(kind)) continue;
    byZone.get(zone as ZoneId)!.set(nodeId, { node_id: nodeId, label, kind, flagged: false });
  }
  return {
    version: 1,
    zones: SCENE_ZONES.map((id) => {
      const items = [...byZone.get(id)!.values()].sort((a, b) => (a.node_id < b.node_id ? -1 : 1));
      return { id, active: items.length > 0, items };
    }),
    findings: [],
    meta: {
      repo,
      commit_sha: "",
      analyzed_at: "",
      stack: "vite_supabase",
      models: {},
      has_db_rules: true,
      unparsed_migrations: [],
      checks_held: 0,
      checks_tested: 7,
    },
  };
}

const MAPPING_STAGE = "Mapping the app";

export type LiveStatus = {
  /** The latest stage message, or null before the first one. */
  stage: string | null;
  /** Findings reported so far. */
  findings: number;
  /** Every part of the app has been found: zones still dark now are really unused. */
  mapped: boolean;
  outcome: "running" | "done" | "error";
  error: string | null;
};

export function liveStatus(events: ProgressEvent[]): LiveStatus {
  const status: LiveStatus = { stage: null, findings: 0, mapped: false, outcome: "running", error: null };
  for (const e of events) {
    if (e.kind === "stage") {
      // The engine reports every node right after "Mapping the app", before its next stage.
      if (status.stage === MAPPING_STAGE) status.mapped = true;
      status.stage = e.message;
    }
    else if (e.kind === "finding") status.findings += 1;
    else if (e.kind === "done") status.outcome = "done";
    else if (e.kind === "error") {
      status.outcome = "error";
      status.error = e.message;
    }
  }
  return status;
}
