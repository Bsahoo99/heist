import { describe, expect, it } from "vitest";
import { boxRect, insideView, placeItems } from "@/components/map/layout";
import { SAMPLE_FINDING, SAMPLE_SCENE } from "@/lib/sampleScene";
import { LANDING_MIN_WIDTH, landingFrame } from "./frame";

const size = { width: 680, height: 440 };

describe("landingFrame", () => {
  const vb = landingFrame(SAMPLE_SCENE, SAMPLE_FINDING.attack_path, size);
  const placed = placeItems(SAMPLE_SCENE);

  it("holds every stop of the route whole", () => {
    for (const s of SAMPLE_FINDING.attack_path) {
      const p = placed.find((x) => x.item.node_id === s.item_id)!;
      expect(insideView(vb, boxRect(p.item.kind, p))).toBe(true);
      expect(vb.hidden).not.toContain(s.item_id);
    }
  });

  it("keeps the box shape and a minimum width", () => {
    expect(vb.width / vb.height).toBeCloseTo(size.width / size.height, 6);
    expect(vb.width).toBeGreaterThanOrEqual(LANDING_MIN_WIDTH);
  });

  it("hides exactly the items it would cut", () => {
    for (const p of placed.filter((x) => !x.overflow)) {
      const whole = insideView(vb, boxRect(p.item.kind, p));
      expect(vb.hidden.includes(p.item.node_id)).toBe(!whole);
    }
  });
});
