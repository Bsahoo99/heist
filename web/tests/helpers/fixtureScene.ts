import type { Scene, SceneItem, SceneZone, Zone as ZoneId } from "@/lib/scene.gen";

type Options = Partial<Record<ZoneId, boolean>> & {
  /** Number of tables in the vault (default 2). */
  tables?: number;
  /** Labels to use for the tables, in order; overrides `tables`. */
  tableLabels?: string[];
};

const item = (node_id: string, label: string, kind: string, flagged = false): SceneItem => ({
  node_id,
  label,
  kind,
  flagged,
});

/** A small, valid Scene for tests. Every zone is active unless set to false. */
export function fixtureScene(opts: Options = {}): Scene {
  const labels =
    opts.tableLabels ?? Array.from({ length: opts.tables ?? 2 }, (_, i) => `table_${i + 1}`);
  const items: Record<ZoneId, SceneItem[]> = {
    street: [item("visitor", "Visitor", "visitor")],
    shop_window: [item("page:src/App.tsx", "App.tsx", "page")],
    guard_desk: [item("auth:supabase", "Supabase Auth", "auth")],
    side_doors: [item("fn:hello", "hello", "function")],
    vault: labels.map((l, i) => item(`table:${l}`, l, "table", i === 0)),
    warehouse: [item("bucket:files", "files", "bucket")],
    across_road: [item("ext:api.example.com", "api.example.com", "external_api")],
  };
  const zones: SceneZone[] = (Object.keys(items) as ZoneId[]).map((id) => {
    const active = opts[id] ?? true;
    return { id, active, items: active ? items[id] : [] };
  });
  return {
    version: 1,
    zones,
    findings: [],
    meta: {
      repo: "fixture",
      commit_sha: "local",
      analyzed_at: "2026-10-26T00:00:00Z",
      stack: "vite_supabase",
      models: {},
      has_db_rules: true,
      unparsed_migrations: [],
      checks_held: 7,
    },
  };
}
