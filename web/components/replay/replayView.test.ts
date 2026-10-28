import { describe, expect, test } from "vitest";
import { makePlan, replayView } from "./replayView";
import { buildTimeline } from "@/lib/timeline";
import { cleanScene, provedFinding, vulnScene } from "@/tests/helpers/scenes";

const m3 = vulnScene.findings.find((f) => f.id === "m3-messages")!;

describe("replayView", () => {
  const plan = makePlan(m3, vulnScene);
  const t = buildTimeline(m3, vulnScene);
  const firstAttack = t.findIndex((e) => e.kind === "attack");

  test("ghost phase grows the ghost line, no attack yet", () => {
    const v = replayView(plan, t, 1, false);
    expect(v.phase).toBe("ghost");
    expect(v.ghost).toEqual(m3.ghost_path.slice(0, 1));
    expect(v.attack).toBeUndefined();
    expect(v.sprite.kind).toBe("ghost");
    expect(v.sprite.leg.length).toBeGreaterThan(1);
    expect(v.sprite.start).toBe(t[1].at);
    expect(v.sprite.walkMs).toBeGreaterThan(0);
    expect(v.sprite.walkMs).toBeLessThan(t[2].at - t[1].at);
  });

  test("attack phase shows the whole ghost and draws the attack up to the last stop", () => {
    const v = replayView(plan, t, firstAttack + 1, false);
    expect(v.phase).toBe("attack");
    expect(v.ghost).toEqual(m3.ghost_path);
    expect(v.attack).toEqual(m3.attack_path);
    expect(v.progress).toBe(0);
    const later = replayView(plan, t, firstAttack + 2, false);
    expect(later.progress).toBeGreaterThan(0);
    expect(later.progress).toBeLessThan(1);
    expect(later.highlight?.nodeId).toBe(m3.attack_path[2].item_id);
  });

  test("reduced motion: no walking, lines drawn to the current stop", () => {
    const v = replayView(plan, t, firstAttack + 1, true);
    expect(v.sprite.leg).toHaveLength(1);
    expect(v.progress).toBeGreaterThan(0);
    expect(replayView(plan, t, 1, true).ghost).toEqual(m3.ghost_path.slice(0, 2));
  });

  test("player index stays on the last step through proof and end", () => {
    const p = makePlan(provedFinding, vulnScene);
    const tp = buildTimeline(provedFinding, vulnScene);
    const proof = replayView(p, tp, tp.length - 2, false);
    expect(proof.phase).toBe("proof");
    expect(proof.stepIndex).toBe(p.steps.length - 1);
    expect(proof.progress).toBe(1);
    expect(replayView(p, tp, tp.length - 1, false).phase).toBe("end");
  });

  test("camera follows the current path", () => {
    expect(replayView(plan, t, 1, false).camera).toEqual({ steps: m3.ghost_path, index: 1, mode: "neighbours" });
    expect(replayView(plan, t, firstAttack, false).camera).toEqual({
      steps: m3.attack_path,
      index: 0,
      mode: "neighbours",
    });
  });
});

describe("replayView, clean app", () => {
  const plan = makePlan(null, cleanScene);
  const t = buildTimeline(null, cleanScene);

  test("each door gets a Lock held marker once the attacker reaches it", () => {
    const v = replayView(plan, t, 2, false);
    expect(v.phase).toBe("lock-held");
    expect(v.markers.map((m) => m.zone)).toEqual(["guard_desk", "side_doors", "vault"]);
    expect(v.markers.slice(0, 2).every((m) => m.appearAt === null)).toBe(true);
    expect(v.markers[2].appearAt).toBe(v.sprite.start + v.sprite.walkMs);
    expect(v.camera).toEqual({ steps: plan.steps.map((s) => s.step), index: 2, mode: "zone" });
    expect(v.ghost).toBeUndefined();
    expect(v.attack).toBeUndefined();
  });

  test("the end shows every marker and frames every door", () => {
    const v = replayView(plan, t, t.length - 1, false);
    expect(v.phase).toBe("end");
    expect(v.markers.map((m) => m.zone)).toEqual(["guard_desk", "side_doors", "vault", "warehouse"]);
    expect(v.markers.every((m) => m.appearAt === null)).toBe(true);
    expect(v.camera).toEqual({ steps: plan.steps.map((s) => s.step), index: 3, mode: "zones" });
  });

  test("the first door is walked to from the visitor", () => {
    const v = replayView(plan, t, 0, false);
    expect(v.sprite.leg.length).toBeGreaterThan(1);
  });
});

describe("placeMarkers", () => {
  test("Lock held markers clear every box, label, title and each other", async () => {
    const { placeMarkers, MARKER } = await import("./replayView");
    const { boxRect, layoutLabels, placeItems, zoneTitles } = await import("@/components/map/layout");
    const plan = makePlan(null, cleanScene);
    const ids = plan.steps.map((s) => s.step.item_id);
    const pts = placeMarkers(cleanScene, ids);
    const placed = placeItems(cleanScene);
    const others = [
      ...placed.map((p) => boxRect(p.item.kind, p)),
      ...layoutLabels(placed).map((l) => l.rect),
      ...zoneTitles().map((t) => t.rect),
    ];
    const rects = pts.map((p) => ({ x: p.x - MARKER.w / 2, y: p.y - MARKER.h / 2, w: MARKER.w, h: MARKER.h }));
    const hit = (a: typeof rects[0], b: typeof rects[0]) =>
      a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
    rects.forEach((r, i) => {
      expect(others.some((o) => hit(o, r))).toBe(false);
      rects.forEach((q, j) => j !== i && expect(hit(r, q)).toBe(false));
      // Near its own item: within 150 px.
      const item = placed.find((p) => p.item.node_id === ids[i])!;
      expect(Math.hypot(pts[i].x - item.x, pts[i].y - item.y)).toBeLessThan(150);
    });
    expect(pts).toEqual(placeMarkers(cleanScene, ids));
  });

  test("a clean app's tries leave no line behind", () => {
    const plan = makePlan(null, cleanScene);
    const t = buildTimeline(null, cleanScene);
    expect(replayView(plan, t, 1, false).sprite.trail).toBe(false);
  });
});

describe("placeMarkers on a narrow map", () => {
  test("clear the narrow map's own, larger labels", async () => {
    const { placeMarkers, MARKER } = await import("./replayView");
    const { layoutLabels, placeItems } = await import("@/components/map/layout");
    const { cameraFrame } = await import("./camera");
    const plan = makePlan(null, cleanScene);
    const steps = plan.steps.map((s) => s.step);
    steps.forEach((_, k) => {
      const f = cameraFrame(cleanScene, steps, k, { width: 358, height: 300 }, { mode: "zone" });
      const scale = Math.min(f.labelScale, 1.4);
      const ids = steps.slice(0, k + 1).map((s) => s.item_id);
      const pts = placeMarkers(cleanScene, ids, { only: f.labelIds, labelScale: f.labelScale, markerScale: scale });
      const labels = layoutLabels(placeItems(cleanScene), { only: f.labelIds, scale: f.labelScale }).map((l) => l.rect);
      for (const p of pts) {
        const r = { x: p.x - (MARKER.w * scale) / 2, y: p.y - (MARKER.h * scale) / 2, w: MARKER.w * scale, h: MARKER.h * scale };
        expect(labels.some((o) => r.x < o.x + o.w && o.x < r.x + r.w && r.y < o.y + o.h && o.y < r.y + r.h)).toBe(false);
      }
    });
  });
});
