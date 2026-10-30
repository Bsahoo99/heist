import { describe, expect, it } from "vitest";
import vuln from "@/tests/fixtures/vuln-scene.json";
import type { Scene } from "./scene.gen";
import type { ProgressEvent } from "./api";
import { liveScene, liveStatus } from "./liveScene";

const stage = (message: string): ProgressEvent => ({ kind: "stage", message, data: {} });
const node = (node_id: string, zone: string, label: string, kind: string): ProgressEvent => ({
  kind: "node_found",
  message: `Found ${label}`,
  data: { zone, label, node_id, kind },
});
const finding = (id: string): ProgressEvent => ({
  kind: "finding",
  message: id,
  data: { id, mistake: 3, severity: "critical", status: "confirmed", title: id },
});

const zone = (s: Scene, id: string) => s.zones.find((z) => z.id === id)!;

describe("liveScene", () => {
  it("starts as an empty block with every zone in order and no findings", () => {
    const s = liveScene([]);
    expect(s.zones.map((z) => z.id)).toEqual([
      "street",
      "shop_window",
      "guard_desk",
      "side_doors",
      "vault",
      "warehouse",
      "across_road",
    ]);
    expect(s.zones.every((z) => !z.active && z.items.length === 0)).toBe(true);
    expect(s.findings).toEqual([]);
  });

  it("lights a zone and adds its item as node_found events arrive", () => {
    const s = liveScene([stage("Mapping the app"), node("table:pets", "vault", "pets", "table")]);
    expect(zone(s, "vault")).toMatchObject({
      active: true,
      items: [{ node_id: "table:pets", label: "pets", kind: "table", flagged: false }],
    });
    expect(zone(s, "warehouse").active).toBe(false);
  });

  it("sorts items by node id, drops duplicates and leaves out hidden kinds", () => {
    const s = liveScene([
      node("table:pets", "vault", "pets", "table"),
      node("table:messages", "vault", "messages", "table"),
      node("table:pets", "vault", "pets", "table"),
      node("policy:pets:read", "vault", "read", "policy"),
      node("client:src/Pets.tsx:9", "shop_window", "from('pets')", "client_call"),
    ]);
    expect(zone(s, "vault").items.map((i) => i.node_id)).toEqual(["table:messages", "table:pets"]);
    // A zone holding only hidden kinds stays dark, as in the final Scene.
    expect(zone(s, "shop_window").active).toBe(false);
  });

  it("ignores malformed node events", () => {
    const bad: ProgressEvent[] = [
      { kind: "node_found", message: "x", data: { zone: "moon", label: "x", node_id: "x", kind: "table" } },
      { kind: "node_found", message: "x", data: { zone: "vault" } },
    ];
    expect(liveScene(bad).zones.every((z) => !z.active)).toBe(true);
  });

  it("matches the final Scene's zones once every node is in", () => {
    const final = vuln as unknown as Scene;
    const events: ProgressEvent[] = final.zones.flatMap((z) =>
      z.items.map((i) => node(i.node_id, z.id, i.label, i.kind)),
    );
    const s = liveScene(events.reverse());
    expect(s.zones.map((z) => ({ id: z.id, active: z.active, items: z.items.map((i) => i.node_id) }))).toEqual(
      final.zones.map((z) => ({ id: z.id, active: z.active, items: z.items.map((i) => i.node_id) })),
    );
  });

  it("is deterministic", () => {
    const events = [node("table:pets", "vault", "pets", "table"), node("fn:a", "side_doors", "a", "function")];
    expect(JSON.stringify(liveScene(events))).toBe(JSON.stringify(liveScene(events)));
  });
});

describe("liveStatus", () => {
  it("is waiting before any event", () => {
    expect(liveStatus([])).toEqual({ stage: null, findings: 0, mapped: false, outcome: "running", error: null });
  });

  it("shows the latest stage and counts findings", () => {
    const s = liveStatus([stage("Mapping the app"), stage("Sorting the findings"), finding("a"), finding("b")]);
    expect(s).toMatchObject({ stage: "Sorting the findings", findings: 2, outcome: "running", error: null });
  });

  it("is mapped once the stage after mapping begins", () => {
    const mapping = [stage("Fetching the repo"), stage("Mapping the app"), node("table:pets", "vault", "pets", "table")];
    expect(liveStatus(mapping).mapped).toBe(false);
    expect(liveStatus([...mapping, stage("Checking the locks")]).mapped).toBe(true);
  });

  it("ends on done or error", () => {
    expect(liveStatus([stage("Done"), { kind: "done", message: "Done", data: {} }]).outcome).toBe("done");
    const err = liveStatus([stage("Fetching the repo"), { kind: "error", message: "Not supported", data: {} }]);
    expect(err).toMatchObject({ outcome: "error", error: "Not supported" });
  });
});
