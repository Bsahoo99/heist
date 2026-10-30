import { describe, expect, it } from "vitest";
import { SAMPLE_FINDING, SAMPLE_SCENE } from "./sampleScene";

describe("sampleScene", () => {
  it("draws its route through items that are on the map", () => {
    const ids = new Set(SAMPLE_SCENE.zones.flatMap((z) => z.items.map((i) => `${z.id}/${i.node_id}`)));
    expect(SAMPLE_FINDING.attack_path.length).toBeGreaterThan(1);
    for (const s of SAMPLE_FINDING.attack_path) expect(ids.has(`${s.zone}/${s.item_id}`)).toBe(true);
  });

  it("flags only the leaked key on the route", () => {
    const flagged = SAMPLE_SCENE.zones.flatMap((z) => z.items.filter((i) => i.flagged).map((i) => i.node_id));
    expect(flagged).toEqual(["env:.env"]);
    expect(SAMPLE_FINDING.attack_path.map((s) => s.item_id)).toContain("env:.env");
  });
});
