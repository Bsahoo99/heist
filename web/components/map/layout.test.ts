import { describe, expect, test } from "vitest";
import {
  SLAB_H,
  VIEWBOX,
  ZONES,
  ZONE_ORDER,
  boxRect,
  cumulativeLengths,
  focusLabelIds,
  focusViewBox,
  gridPosition,
  isoToScreen,
  itemPosition,
  layoutLabels,
  offsetPolyline,
  partialPath,
  pathLength,
  pathStops,
  placeItems,
  routePath,
  truncateLabel,
  zoneTitles,
  type Rect,
} from "./layout";
import { fixtureScene } from "@/tests/helpers/fixtureScene";
import type { PathStep, Scene, Zone as ZoneId } from "@/lib/scene.gen";
import vulnJson from "@/tests/fixtures/vuln-scene.json";
import cleanJson from "@/tests/fixtures/clean-scene.json";

const vulnScene = vulnJson as unknown as Scene;
const cleanScene = cleanJson as unknown as Scene;

const step = (zone: ZoneId, item_id: string): PathStep => ({
  zone,
  item_id,
  node_id: item_id,
  ref: null,
  data: "",
  story: "",
  why: "",
  code: "",
});

const overlaps = (a: Rect, b: Rect) =>
  a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

const contains = (outer: { x: number; y: number; width: number; height: number }, r: Rect) =>
  r.x >= outer.x && r.y >= outer.y && r.x + r.w <= outer.x + outer.width && r.y + r.h <= outer.y + outer.height;

describe("isoToScreen", () => {
  test("projects 2:1", () => {
    expect(isoToScreen(1, 0)).toEqual({ x: 32, y: 16 });
    expect(isoToScreen(0, 1)).toEqual({ x: -32, y: 16 });
    expect(isoToScreen(0, 0)).toEqual({ x: 0, y: 0 });
  });
});

describe("ZONES", () => {
  test("covers every zone id", () => {
    expect(Object.keys(ZONES).sort()).toEqual([...ZONE_ORDER].sort());
  });

  test("has the planned slot counts", () => {
    expect(ZONES.vault.slots).toBe(12);
    expect(ZONES.side_doors.slots).toBe(8);
    expect(ZONES.warehouse.slots).toBe(6);
    expect(ZONES.street.slots).toBe(1);
    expect(ZONES.guard_desk.slots).toBe(1);
  });

  test("zones never overlap", () => {
    const ids = Object.keys(ZONES) as ZoneId[];
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = ZONES[ids[i]];
        const b = ZONES[ids[j]];
        const apart =
          a.origin[0] + a.size[0] <= b.origin[0] ||
          b.origin[0] + b.size[0] <= a.origin[0] ||
          a.origin[1] + a.size[1] <= b.origin[1] ||
          b.origin[1] + b.size[1] <= a.origin[1];
        expect(apart, `${ids[i]} overlaps ${ids[j]}`).toBe(true);
      }
    }
  });

  test("the block reads left to right on screen", () => {
    const centreX = (id: ZoneId) => {
      const z = ZONES[id];
      return isoToScreen(z.origin[0] + z.size[0] / 2, z.origin[1] + z.size[1] / 2).x;
    };
    const order: ZoneId[] = ["across_road", "street", "shop_window", "guard_desk", "side_doors"];
    for (let i = 1; i < order.length; i++) {
      expect(centreX(order[i]), `${order[i]} right of ${order[i - 1]}`).toBeGreaterThan(centreX(order[i - 1]));
    }
    expect(centreX("vault")).toBeGreaterThan(centreX("side_doors"));
    expect(centreX("warehouse")).toBeGreaterThan(centreX("side_doors"));
  });

  test("the street runs along y at the left edge, rooms chain along x", () => {
    const s = ZONES.street;
    expect(s.size[1]).toBeGreaterThan(s.size[0]);
    const rooms: ZoneId[] = ["shop_window", "guard_desk", "side_doors", "vault"];
    for (const id of rooms) expect(ZONES[id].origin[0]).toBeGreaterThanOrEqual(s.origin[0] + s.size[0]);
    expect(ZONES.across_road.origin[0] + ZONES.across_road.size[0]).toBeLessThanOrEqual(s.origin[0]);
  });

  test("every slot sits inside its zone and slots are distinct", () => {
    for (const id of ZONE_ORDER) {
      const z = ZONES[id];
      const seen = new Set<string>();
      for (let s = 0; s < z.slots; s++) {
        const [gx, gy] = gridPosition(id, s);
        expect(gx).toBeGreaterThan(z.origin[0]);
        expect(gx).toBeLessThan(z.origin[0] + z.size[0]);
        expect(gy).toBeGreaterThan(z.origin[1]);
        expect(gy).toBeLessThan(z.origin[1] + z.size[1]);
        seen.add(`${gx},${gy}`);
      }
      expect(seen.size).toBe(z.slots);
    }
  });
});

describe("VIEWBOX", () => {
  test("is close to 16:9", () => {
    const ratio = VIEWBOX.width / VIEWBOX.height;
    expect(ratio).toBeGreaterThan(1.6);
    expect(ratio).toBeLessThan(2.0);
  });

  test("holds every item, label and title of a full scene", () => {
    const scene = fixtureScene({ tables: 12 });
    const placed = placeItems(scene);
    for (const p of placed) expect(contains(VIEWBOX, boxRect(p.item.kind, p)), p.item.node_id).toBe(true);
    for (const l of layoutLabels(placed)) expect(contains(VIEWBOX, l.rect), l.nodeId).toBe(true);
    for (const t of zoneTitles()) expect(contains(VIEWBOX, t.rect), t.zone).toBe(true);
  });
});

describe("itemPosition", () => {
  test("is the projected slot centre", () => {
    const [gx, gy] = gridPosition("vault", 3);
    expect(itemPosition("vault", 3)).toEqual(isoToScreen(gx, gy));
  });

  test("overflow slots share the last slot", () => {
    expect(itemPosition("vault", 12)).toEqual(itemPosition("vault", 11));
    expect(itemPosition("vault", 40)).toEqual(itemPosition("vault", 11));
  });
});

describe("placeItems", () => {
  test("puts extras behind the last slot and counts them", () => {
    const placed = placeItems(fixtureScene({ tables: 15 })).filter((p) => p.zone === "vault");
    expect(placed).toHaveLength(15);
    expect(placed.filter((p) => p.overflow)).toHaveLength(3);
    const last = placed.find((p) => p.slot === 11 && !p.overflow);
    expect(last?.extra).toBe(3);
    expect(placed.filter((p) => p.extra > 0)).toHaveLength(1);
  });

  test("no extra count when the zone fits", () => {
    const placed = placeItems(fixtureScene({ tables: 12 }));
    expect(placed.every((p) => p.extra === 0 && !p.overflow)).toBe(true);
  });
});

describe("layoutLabels", () => {
  const longTables = Array.from({ length: 12 }, (_, i) => `customer_records_${i + 1}`);
  const scenes: [string, Scene][] = [
    ["vuln", vulnScene],
    ["clean", cleanScene],
    ["12-table vault", fixtureScene({ tables: 12 })],
    ["12 long table names", fixtureScene({ tableLabels: longTables })],
    ["15 tables (overflow)", fixtureScene({ tableLabels: [...longTables, "a", "b", "c"] })],
  ];

  test.each(scenes)("%s: no label overlaps another label, another item or a zone title", (_, scene) => {
    const placed = placeItems(scene);
    const labels = layoutLabels(placed);
    const titles = zoneTitles();
    for (let i = 0; i < labels.length; i++) {
      for (let j = i + 1; j < labels.length; j++) {
        expect(overlaps(labels[i].rect, labels[j].rect), `${labels[i].nodeId} / ${labels[j].nodeId}`).toBe(false);
      }
      for (const p of placed) {
        if (p.overflow || p.item.node_id === labels[i].nodeId) continue;
        expect(overlaps(labels[i].rect, boxRect(p.item.kind, p)), `${labels[i].nodeId} on ${p.item.node_id}`).toBe(false);
      }
      for (const t of titles) expect(overlaps(labels[i].rect, t.rect), `${labels[i].nodeId} on ${t.zone}`).toBe(false);
    }
  });

  test("zone titles clear every item box of a full block", () => {
    const full = fixtureScene({ tables: 12 });
    for (const z of full.zones) {
      const n = ZONES[z.id].slots;
      if (z.id !== "vault") {
        const kind = z.items[0]?.kind ?? ZONES[z.id].kind;
        z.items = Array.from({ length: n }, (_, i) => ({ node_id: `${z.id}:${i}`, label: `${i}`, kind, flagged: false }));
      }
    }
    const placed = placeItems(full);
    for (const t of zoneTitles()) {
      for (const p of placed) expect(overlaps(t.rect, boxRect(p.item.kind, p)), `${t.zone} on ${p.item.node_id}`).toBe(false);
    }
  });

  test("labels sit in front of their item's front corner", () => {
    const placed = placeItems(vulnScene);
    for (const l of layoutLabels(placed)) {
      const p = placed.find((q) => q.item.node_id === l.nodeId)!;
      const box = boxRect(p.item.kind, p);
      expect(l.rect.y).toBeGreaterThanOrEqual(box.y + box.h + 4);
    }
  });

  test.each([1, 2, 3.5])("zone titles never overlap each other at scale %s", (scale) => {
    const titles = zoneTitles(scale);
    for (let i = 0; i < titles.length; i++) {
      for (let j = i + 1; j < titles.length; j++) expect(overlaps(titles[i].rect, titles[j].rect)).toBe(false);
    }
  });

  test("only shows the requested labels, scaled", () => {
    const labels = layoutLabels(placeItems(vulnScene), { only: new Set(["visitor"]), scale: 2 });
    expect(labels.map((l) => l.nodeId)).toEqual(["visitor"]);
    expect(labels[0].font).toBe(28);
  });

  test("puts +N on the last slot of an overflowing zone", () => {
    const labels = layoutLabels(placeItems(fixtureScene({ tables: 15 })));
    expect(labels.filter((l) => l.badge)).toEqual([expect.objectContaining({ badge: "+3" })]);
    expect(labels.filter((l) => l.zone === "vault")).toHaveLength(12);
  });
});

describe("pathStops", () => {
  const scene = fixtureScene({ tables: 3 });

  test("stacks repeated steps and skips unknown items", () => {
    const stops = pathStops(
      [step("street", "visitor"), step("vault", "table:table_1"), step("vault", "table:table_1"), step("vault", "table:nope")],
      scene,
    );
    expect(stops.map((s) => [s.itemId, s.count])).toEqual([
      ["visitor", 1],
      ["table:table_1", 2],
    ]);
  });
});

describe("routePath", () => {
  const scene = fixtureScene({ tables: 3 });
  const isAxis = (a: { x: number; y: number }, b: { x: number; y: number }) =>
    Math.abs(Math.abs(b.x - a.x) - 2 * Math.abs(b.y - a.y)) < 1e-6;

  test("walking legs run along the grid axes and end on each stop", () => {
    const steps = [step("street", "visitor"), step("guard_desk", "auth:supabase"), step("vault", "table:table_2")];
    const r = routePath(steps, scene);
    expect(r.stops.map((s) => s.itemId)).toEqual(["visitor", "auth:supabase", "table:table_2"]);
    for (let i = 1; i < r.points.length; i++) expect(isAxis(r.points[i - 1], r.points[i])).toBe(true);
    const slot = itemPosition("vault", 1);
    expect(r.points[r.stops[2].index]).toEqual({ x: slot.x, y: slot.y - SLAB_H });
  });

  test("a leg moving right enters the room along x, through its street-facing edge", () => {
    const r = routePath([step("street", "visitor"), step("guard_desk", "auth:supabase")], scene);
    const [a, b] = r.points.slice(-2);
    // Last leg runs along +x: screen right and down at 2:1.
    expect(b.x - a.x).toBeGreaterThan(0);
    expect(b.y - a.y).toBeGreaterThan(0);
  });

  test("a leg to across the road is a curved call, not a walk", () => {
    const r = routePath([step("side_doors", "fn:hello"), step("across_road", "ext:api.example.com")], scene);
    expect(r.points.length).toBeGreaterThan(10);
    const axisSegments = r.points.slice(1).filter((p, i) => isAxis(r.points[i], p)).length;
    expect(axisSegments).toBeLessThan(r.points.length - 1);
    // The arc bulges above both ends.
    const top = Math.min(...r.points.map((p) => p.y));
    expect(top).toBeLessThan(Math.min(r.points[0].y, r.points[r.points.length - 1].y));
  });

  test("even the longest call arc stays inside the frame", () => {
    const scene = fixtureScene({ tables: 12 });
    const r = routePath([step("vault", "table:table_12"), step("across_road", "ext:api.example.com")], scene);
    expect(Math.min(...r.points.map((p) => p.y))).toBeGreaterThanOrEqual(VIEWBOX.y + 12);
  });

  test("stacked steps make one stop with a count and no zero-length segment", () => {
    const r = routePath([step("street", "visitor"), step("vault", "table:table_1"), step("vault", "table:table_1")], scene);
    expect(r.stops).toHaveLength(2);
    expect(r.stops[1].count).toBe(2);
    for (let i = 1; i < r.points.length; i++) {
      expect(Math.hypot(r.points[i].x - r.points[i - 1].x, r.points[i].y - r.points[i - 1].y)).toBeGreaterThan(0);
    }
  });
});

describe("offsetPolyline", () => {
  test("shifts each segment sideways by the distance", () => {
    const line = [
      { x: 0, y: 0 },
      { x: 10, y: 0 },
    ];
    expect(offsetPolyline(line, 4)).toEqual([
      { x: 0, y: -4 },
      { x: 10, y: -4 },
    ]);
  });

  test("two opposite offsets of one path never coincide", () => {
    const r = routePath(
      [step("street", "visitor"), step("guard_desk", "auth:supabase"), step("vault", "table:table_1")],
      fixtureScene(),
    );
    const a = offsetPolyline(r.points, -4);
    const b = offsetPolyline(r.points, 4);
    a.forEach((p, i) => expect(Math.hypot(p.x - b[i].x, p.y - b[i].y)).toBeGreaterThanOrEqual(8 - 1e-6));
  });
});

describe("partialPath", () => {
  const route = routePath(
    [step("street", "visitor"), step("guard_desk", "auth:supabase"), step("across_road", "ext:api.example.com")],
    fixtureScene(),
  ).points;

  test("cuts the routed line by real length", () => {
    const total = pathLength(route);
    expect(pathLength(partialPath(route, 0.5))).toBeCloseTo(total / 2, 6);
    expect(pathLength(partialPath(route, 0.25))).toBeCloseTo(total / 4, 6);
    expect(partialPath(route, 1)).toEqual(route);
    expect(partialPath(route, 0)).toEqual([]);
  });

  test("cumulative lengths end at the total", () => {
    const cum = cumulativeLengths(route);
    expect(cum[0]).toBe(0);
    expect(cum[cum.length - 1]).toBeCloseTo(pathLength(route), 6);
  });
});

describe("focusViewBox", () => {
  const finding = vulnScene.findings.find((f) => f.id === "m3-messages")!;

  test("frames the routes, the street and the visitor", () => {
    const { viewBox } = focusViewBox(vulnScene, finding.ghost_path, finding.attack_path);
    for (const r of [routePath(finding.ghost_path, vulnScene), routePath(finding.attack_path, vulnScene)]) {
      for (const p of r.points) expect(contains(viewBox, { x: p.x, y: p.y, w: 0, h: 0 })).toBe(true);
    }
    const s = ZONES.street;
    for (const [gx, gy] of [
      [s.origin[0], s.origin[1]],
      [s.origin[0] + s.size[0], s.origin[1] + s.size[1]],
    ]) {
      const c = isoToScreen(gx, gy);
      expect(contains(viewBox, { x: c.x, y: c.y, w: 0, h: 0 })).toBe(true);
    }
  });

  test("the titles of the zones on the path are in the frame", () => {
    const m1 = vulnScene.findings.find((f) => f.id === "m1-vite-openai-api-key")!;
    const { viewBox, labelScale } = focusViewBox(vulnScene, m1.ghost_path, m1.attack_path);
    for (const t of zoneTitles(labelScale)) {
      if (["street", "shop_window", "across_road"].includes(t.zone)) expect(contains(viewBox, t.rect), t.zone).toBe(true);
    }
  });

  test("a finding that stays near the street gets a tighter frame", () => {
    const m1 = vulnScene.findings.find((f) => f.id === "m1-vite-openai-api-key")!;
    const { viewBox, labelScale } = focusViewBox(vulnScene, m1.ghost_path, m1.attack_path);
    expect(viewBox.width).toBeLessThan(VIEWBOX.width * 0.7);
    expect(labelScale).toBeGreaterThan(1);
  });

  test("is deterministic and falls back to the whole block without paths", () => {
    expect(focusViewBox(vulnScene, finding.ghost_path, finding.attack_path)).toEqual(
      focusViewBox(vulnScene, finding.ghost_path, finding.attack_path),
    );
    const whole = focusViewBox(cleanScene).viewBox;
    expect(contains(whole, { x: VIEWBOX.x, y: VIEWBOX.y, w: VIEWBOX.width, h: VIEWBOX.height })).toBe(true);
    for (const t of zoneTitles(focusViewBox(cleanScene).labelScale)) expect(contains(whole, t.rect), t.zone).toBe(true);
  });

  test("labels path items and flagged items only", () => {
    const ids = focusLabelIds(cleanScene, [step("street", "visitor")], [step("vault", "table:pets")]);
    expect([...ids].sort()).toEqual(["table:pets", "visitor"]);
  });
});

describe("truncateLabel", () => {
  test("keeps short labels and ellipsizes long ones", () => {
    expect(truncateLabel("pets", 12)).toBe("pets");
    expect(truncateLabel("adoption_requests_archive", 12)).toBe("adoption_re…");
    expect(truncateLabel("adoption_requests_archive", 12)).toHaveLength(12);
  });
});
