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
