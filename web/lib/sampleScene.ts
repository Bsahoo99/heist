// The landing page's picture: a sample app's block with one break-in drawn on it.
// A hand-trimmed copy of the vuln fixture's zones and its leaked-key attack route,
// kept here so product code never imports test fixtures. Decoration only.
import type { PathStep, Scene, SceneFinding, SceneItem, Zone } from "./scene.gen";

const item = (node_id: string, label: string, kind: string, flagged = false): SceneItem => ({
  node_id,
  label,
  kind,
  flagged,
});

const step = (zone: Zone, item_id: string): PathStep => ({
  zone,
  item_id,
  node_id: item_id,
  ref: null,
  data: "",
  story: "",
  why: "",
  code: "",
});

export const SAMPLE_SCENE: Scene = {
  version: 1,
  zones: [
    {
      id: "street",
      active: true,
      items: [item("visitor", "Visitor", "visitor")],
    },
    {
      id: "shop_window",
      active: true,
      items: [
        item("env:.env", ".env", "env_file", true),
        item("page:src/pages/Pets.tsx", "Pets.tsx", "page"),
        item("page:src/pages/Requests.tsx", "Requests.tsx", "page"),
        item("page:src/pages/Upload.tsx", "Upload.tsx", "page"),
      ],
    },
    {
      id: "guard_desk",
      active: true,
      items: [item("auth:supabase", "Supabase Auth", "auth")],
    },
    {
      id: "side_doors",
      active: true,
      items: [
        item("fn:ai-describe", "ai-describe", "function"),
        item("fn:send-email", "send-email", "function"),
        item("fn:update-request", "update-request", "function"),
      ],
    },
    {
      id: "vault",
      active: true,
      items: [
        item("table:adoption_requests", "adoption_requests", "table"),
        item("table:messages", "messages", "table"),
        item("table:notes", "notes", "table"),
        item("table:pets", "pets", "table"),
        item("table:profiles", "profiles", "table"),
      ],
    },
    {
      id: "warehouse",
      active: true,
      items: [
        item("bucket:id-documents", "id-documents", "bucket"),
        item("bucket:pet-photos", "pet-photos", "bucket"),
      ],
    },
    {
      id: "across_road",
      active: true,
      items: [
        item("ext:api.openai.com", "api.openai.com", "external_api"),
        item("ext:api.resend.com", "api.resend.com", "external_api"),
      ],
    },
  ],
  findings: [],
  meta: {
    repo: "a sample app",
    commit_sha: "",
    analyzed_at: "",
    stack: "vite_supabase",
    models: {},
    has_db_rules: true,
    unparsed_migrations: [],
    checks_held: 0,
  },
};

/** A visitor looks through the shop window, reads the key off .env and spends it across the road. */
export const SAMPLE_FINDING: SceneFinding = {
  id: "sample",
  mistake: 1,
  severity: "critical",
  status: "confirmed",
  title: "",
  trace_source: "fallback",
  ghost_path: [],
  attack_path: [
    step("street", "visitor"),
    step("shop_window", "page:src/pages/Pets.tsx"),
    step("shop_window", "env:.env"),
    step("across_road", "ext:api.openai.com"),
  ],
  guard_ref: { file: "", start_line: 1, end_line: 1 },
  proof_rows: [],
  fix: { diff: "", explanation: "", prompt: "" },
};
