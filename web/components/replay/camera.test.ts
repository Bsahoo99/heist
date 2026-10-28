import { describe, expect, test } from "vitest";
import { CAMERA_MIN_WIDTH, cameraFrame } from "./camera";
import { legPoints, stepStopIndices, stopFraction } from "./geometry";
import {
  VIEWBOX,
  ZONES,
  boxRect,
  cumulativeLengths,
  insideView,
  isoToScreen,
  offsetPolyline,
  placeItems,
  routePath,
} from "@/components/map/layout";
import { PATH_OFFSET } from "@/components/map/Paths";
import { replaySteps } from "@/lib/timeline";
import type { PathStep } from "@/lib/scene.gen";
import { cleanScene, vulnScene } from "@/tests/helpers/scenes";

const SIZE = { width: 358, height: 300 };
const placed = placeItems(vulnScene);
const box = (id: string) => {
  const p = placed.find((q) => q.item.node_id === id)!;
  return boxRect(p.item.kind, p);
};
const finding = (id: string) => vulnScene.findings.find((f) => f.id === id)!;

describe("cameraFrame", () => {
  const steps = finding("m1-vite-openai-api-key").attack_path;

  test("frames the step and its neighbours", () => {
    for (let i = 0; i < steps.length; i++) {
      const { viewBox } = cameraFrame(vulnScene, steps, i, SIZE);
      for (const j of [i - 1, i, i + 1]) {
        if (j < 0 || j >= steps.length) continue;
        expect(insideView(viewBox, box(steps[j].item_id))).toBe(true);
      }
    }
  });

  test("labels only the step and its neighbours", () => {
    const { labelIds } = cameraFrame(vulnScene, steps, 2, SIZE);
    expect([...labelIds].sort()).toEqual([steps[1].item_id, steps[2].item_id, steps[3].item_id].sort());
  });

  test("step 0 includes the street", () => {
    const { viewBox } = cameraFrame(vulnScene, steps, 0, SIZE);
    const z = ZONES.street;
    const corners = [
      isoToScreen(z.origin[0], z.origin[1]),
      isoToScreen(z.origin[0] + z.size[0], z.origin[1] + z.size[1]),
    ];
    for (const c of corners) expect(insideView(viewBox, { x: c.x, y: c.y, w: 0, h: 0 })).toBe(true);
  });

  test("matches the container's aspect ratio and keeps a minimum width", () => {
    for (let i = 0; i < steps.length; i++) {
      const { viewBox } = cameraFrame(vulnScene, steps, i, SIZE);
      expect(viewBox.width / viewBox.height).toBeCloseTo(SIZE.width / SIZE.height, 2);
      expect(viewBox.width).toBeGreaterThanOrEqual(CAMERA_MIN_WIDTH);
    }
  });

  test("a mid-route frame is tighter than the whole block", () => {
    const route = finding("m3-messages").attack_path;
    const { viewBox } = cameraFrame(vulnScene, route, 2, SIZE);
    expect(viewBox.width).toBeLessThan(VIEWBOX.width * 0.8);
  });

  test("zone mode frames the whole zone being tested", () => {
    const lockSteps = replaySteps(null, cleanScene).map((s) => s.step);
    lockSteps.forEach((s, i) => {
      const { viewBox } = cameraFrame(cleanScene, lockSteps, i, SIZE, { mode: "zone" });
      const z = ZONES[s.zone];
      const corners = [
        isoToScreen(z.origin[0], z.origin[1]),
        isoToScreen(z.origin[0] + z.size[0], z.origin[1]),
        isoToScreen(z.origin[0], z.origin[1] + z.size[1]),
        isoToScreen(z.origin[0] + z.size[0], z.origin[1] + z.size[1]),
      ];
      for (const c of corners) expect(insideView(viewBox, { x: c.x, y: c.y, w: 0, h: 0 })).toBe(true);
    });
  });

  test("zones mode frames every door tried; extra rects are framed too", () => {
    const lockSteps = replaySteps(null, cleanScene).map((s) => s.step);
    const extra = { x: 900, y: -400, w: 50, h: 20 };
    const { viewBox, labelIds } = cameraFrame(cleanScene, lockSteps, 3, SIZE, { mode: "zones", extra: [extra] });
    for (const s of lockSteps) {
      const z = ZONES[s.zone];
      const c = isoToScreen(z.origin[0] + z.size[0], z.origin[1] + z.size[1]);
      expect(insideView(viewBox, { x: c.x, y: c.y, w: 0, h: 0 })).toBe(true);
    }
    expect(insideView(viewBox, extra)).toBe(true);
    expect(labelIds.size).toBe(0);
  });

  test("deterministic", () => {
    expect(cameraFrame(vulnScene, steps, 1, SIZE)).toEqual(cameraFrame(vulnScene, steps, 1, SIZE));
  });
});

describe("replay geometry", () => {
  const step = (item_id: string): PathStep => ({
    zone: placed.find((p) => p.item.node_id === item_id)!.zone,
    item_id,
    node_id: item_id,
    ref: null,
    data: "",
    story: "",
    why: "",
    code: "",
  });

  test("steps map to their stop; repeats share one, unknown items keep the previous", () => {
    const steps = [step("visitor"), step("auth:supabase"), step("auth:supabase"), { ...step("visitor"), item_id: "nope" }, step("table:messages")];
    expect(stepStopIndices(steps, vulnScene)).toEqual([0, 1, 1, 1, 2]);
  });

  test("a leg runs from one stop to the next along the drawn line", () => {
    const steps = finding("m3-messages").attack_path;
    const route = routePath(steps, vulnScene);
    const line = offsetPolyline(route.points, PATH_OFFSET.attack);
    const leg = legPoints(route, PATH_OFFSET.attack, 0, 1);
    expect(leg[0]).toEqual(line[route.stops[0].index]);
    expect(leg.at(-1)).toEqual(line[route.stops[1].index]);
  });

  test("stopFraction is the drawn share of the line at that stop", () => {
    const steps = finding("m3-messages").attack_path;
    const route = routePath(steps, vulnScene);
    const cum = cumulativeLengths(offsetPolyline(route.points, PATH_OFFSET.attack));
    expect(stopFraction(route, PATH_OFFSET.attack, 0)).toBe(0);
    expect(stopFraction(route, PATH_OFFSET.attack, 1)).toBeCloseTo(cum[route.stops[1].index] / cum.at(-1)!, 6);
    expect(stopFraction(route, PATH_OFFSET.attack, route.stops.length - 1)).toBe(1);
  });
});

describe("cameraFrame labels and titles", () => {
  test("every label and title it asks for fits inside the frame", async () => {
    const { layoutLabels, zoneTitles } = await import("@/components/map/layout");
    for (const f of vulnScene.findings) {
      for (const steps of [f.ghost_path, f.attack_path]) {
        steps.forEach((_, i) => {
          const frame = cameraFrame(vulnScene, steps, i, SIZE);
          for (const l of layoutLabels(placed, { only: frame.labelIds, scale: frame.labelScale })) {
            expect(insideView(frame.viewBox, l.rect)).toBe(true);
          }
          for (const t of zoneTitles(frame.labelScale).filter((t) => frame.titleZones.has(t.zone))) {
            expect(insideView(frame.viewBox, t.rect)).toBe(true);
          }
        });
      }
    }
  });
});

describe("wideFrame", () => {
  const WIDE = { width: 2, height: 1 };

  test("frames every ghost and attack stop plus the street, steady for the whole finding", async () => {
    const { wideFrame, WIDE_MIN_WIDTH } = await import("./camera");
    for (const f of vulnScene.findings) {
      const vb = wideFrame(vulnScene, f, WIDE);
      for (const s of [...f.ghost_path, ...f.attack_path]) {
        if (placed.some((p) => p.item.node_id === s.item_id)) expect(insideView(vb, box(s.item_id))).toBe(true);
      }
      const z = ZONES.street;
      for (const c of [isoToScreen(z.origin[0], z.origin[1]), isoToScreen(z.origin[0] + z.size[0], z.origin[1] + z.size[1])]) {
        expect(insideView(vb, { x: c.x, y: c.y, w: 0, h: 0 })).toBe(true);
      }
      expect(vb.width).toBeGreaterThanOrEqual(WIDE_MIN_WIDTH);
      expect(vb.width / vb.height).toBeCloseTo(2, 2);
    }
  });

  test("a short route zooms in on the block", async () => {
    const { wideFrame } = await import("./camera");
    expect(wideFrame(vulnScene, finding("m1-vite-openai-api-key"), WIDE).width).toBeLessThan(VIEWBOX.width * 0.75);
  });

  test("labels of the route's items fit inside", async () => {
    const { wideFrame } = await import("./camera");
    const { layoutLabels } = await import("@/components/map/layout");
    for (const f of vulnScene.findings) {
      const vb = wideFrame(vulnScene, f, WIDE);
      const ids = new Set([...f.ghost_path, ...f.attack_path].map((s) => s.item_id));
      for (const l of layoutLabels(placed).filter((l) => ids.has(l.nodeId))) expect(insideView(vb, l.rect)).toBe(true);
    }
  });

  test("clean app: the active doors, guard desk to warehouse, and extra rects", async () => {
    const { wideFrame } = await import("./camera");
    const extra = { x: 1000, y: -300, w: 10, h: 10 };
    const vb = wideFrame(cleanScene, null, WIDE, { extra: [extra] });
    for (const id of ["guard_desk", "side_doors", "vault", "warehouse"] as const) {
      const z = ZONES[id];
      for (const c of [isoToScreen(z.origin[0], z.origin[1]), isoToScreen(z.origin[0] + z.size[0], z.origin[1] + z.size[1])]) {
        expect(insideView(vb, { x: c.x, y: c.y, w: 0, h: 0 })).toBe(true);
      }
    }
    expect(insideView(vb, extra)).toBe(true);
  });

  test("deterministic", async () => {
    const { wideFrame } = await import("./camera");
    const f = finding("m3-messages");
    expect(wideFrame(vulnScene, f, WIDE)).toEqual(wideFrame(vulnScene, f, WIDE));
  });
});

describe("pickCorner", () => {
  const vb = { x: 0, y: 0, width: 1000, height: 500 };
  const card = { w: 0.4, h: 0.3 };

  test("takes the first free corner, bottom-left first", async () => {
    const { pickCorner } = await import("./camera");
    expect(pickCorner(vb, card, [])).toBe("bottom-left");
    expect(pickCorner(vb, card, [{ x: 50, y: 450, w: 10, h: 10 }])).toBe("top-right");
  });

  test("with no free corner, the one covering the least", async () => {
    const { pickCorner } = await import("./camera");
    const everywhere = [
      { x: 30, y: 30, w: 10, h: 10 },
      { x: 50, y: 60, w: 10, h: 10 },
      { x: 900, y: 30, w: 10, h: 10 },
      { x: 30, y: 450, w: 10, h: 10 },
      { x: 40, y: 440, w: 10, h: 10 },
      { x: 900, y: 450, w: 10, h: 10 },
    ];
    expect(pickCorner(vb, card, everywhere)).toBe("top-right");
  });

  test("the proof card on the wide frame stays off the route and the vault box", async () => {
    const { pickCorner, wideFrame, cornerRect } = await import("./camera");
    const { provedFinding } = await import("@/tests/helpers/scenes");
    const f = provedFinding;
    const frame = wideFrame(vulnScene, f, { width: 2, height: 1 });
    const route = [routePath(f.ghost_path, vulnScene), routePath(f.attack_path, vulnScene)].flatMap((r) =>
      r.points.map((p) => ({ x: p.x, y: p.y, w: 0, h: 0 })),
    );
    const obstacles = [...route, box(f.attack_path.at(-1)!.item_id)];
    const corner = pickCorner(frame, { w: 0.43, h: 0.34 }, obstacles);
    const r = cornerRect(frame, { w: 0.43, h: 0.34 }, corner);
    const hit = (a: typeof r, b: typeof r) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
    expect(obstacles.some((o) => hit(r, { ...o, w: Math.max(o.w, 0.01), h: Math.max(o.h, 0.01) }))).toBe(false);
  });
});

describe("wideFrame edges", () => {
  const crosses = (vb: { x: number; y: number; width: number; height: number }, r: { x: number; y: number; w: number; h: number }) => {
    const overlaps = r.x < vb.x + vb.width && vb.x < r.x + r.w && r.y < vb.y + vb.height && vb.y < r.y + r.h;
    return overlaps && !insideView(vb, r);
  };

  test("the m3 proved frame holds every vault box whole", async () => {
    const { wideFrame } = await import("./camera");
    const { provedFinding } = await import("@/tests/helpers/scenes");
    for (const size of [{ width: 892, height: 438 }, { width: 1248, height: 540 }, { width: 1888, height: 900 }]) {
      const vb = wideFrame(vulnScene, provedFinding, size);
      for (const p of placed.filter((q) => q.zone === "vault" && !q.overflow)) {
        expect(insideView(vb, boxRect(p.item.kind, p))).toBe(true);
      }
    }
  });

  test("no drawn item box crosses the frame edge, for any finding or the clean scene", async () => {
    const { wideFrame } = await import("./camera");
    const { provedFinding } = await import("@/tests/helpers/scenes");
    const cases = [
      ...vulnScene.findings.map((f) => [vulnScene, f] as const),
      [vulnScene, provedFinding] as const,
      [cleanScene, null] as const,
    ];
    for (const size of [{ width: 892, height: 438 }, { width: 1248, height: 540 }, { width: 1888, height: 900 }, { width: 992, height: 590 }]) {
      for (const [scene, f] of cases) {
        const vb = wideFrame(scene, f, size);
        const hidden = new Set(vb.hidden);
        for (const p of placeItems(scene).filter((q) => !q.overflow && !hidden.has(q.item.node_id))) {
          expect(crosses(vb, boxRect(p.item.kind, p)), `${f?.id ?? "clean"} ${p.item.node_id} ${size.width}`).toBe(false);
        }
      }
    }
  });

  test("respects the given aspect", async () => {
    const { wideFrame } = await import("./camera");
    for (const size of [{ width: 1.68, height: 1 }, { width: 1.95, height: 1 }, { width: 2.09, height: 1 }, { width: 2.31, height: 1 }]) {
      for (const f of [vulnScene.findings[0], vulnScene.findings[2], null]) {
        const vb = wideFrame(f ? vulnScene : cleanScene, f, size);
        expect(vb.width / vb.height).toBeCloseTo(size.width / size.height, 2);
      }
    }
  });
});

describe("wideFrame on a big box", () => {
  test("never draws the map past the maximum screen scale", async () => {
    const { wideFrame, WIDE_MAX_SCALE } = await import("./camera");
    const size = { width: 1886, height: 900 };
    for (const f of vulnScene.findings) {
      expect(size.width / wideFrame(vulnScene, f, size).width).toBeLessThanOrEqual(WIDE_MAX_SCALE + 1e-6);
    }
  });
});
