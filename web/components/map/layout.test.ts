import { describe, expect, test } from "vitest";
import {
  SLAB_H,
  ZONES,
  ZONE_ORDER,
  gridPosition,
  isoToScreen,
  itemPosition,
  pathPoints,
  placeItems,
  reachedStops,
  truncateLabel,
} from "./layout";
import { fixtureScene } from "@/tests/helpers/fixtureScene";
import type { PathStep, Zone as ZoneId } from "@/lib/scene.gen";

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
    const scene = fixtureScene({ tables: 15 });
    const placed = placeItems(scene).filter((p) => p.zone === "vault");
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

describe("pathPoints", () => {
  const scene = fixtureScene({ tables: 3 });

  test("follows item positions in order", () => {
    const pts = pathPoints(
      [step("street", "visitor"), step("guard_desk", "auth:supabase"), step("vault", "table:table_2")],
      scene,
    );
    expect(pts.map((p) => p.itemId)).toEqual(["visitor", "auth:supabase", "table:table_2"]);
    const slot = itemPosition("vault", 1);
    expect(pts[2]).toMatchObject({ x: slot.x, y: slot.y - SLAB_H });
  });

  test("stacks repeated steps on the same item into one point", () => {
    const pts = pathPoints(
      [step("street", "visitor"), step("vault", "table:table_1"), step("vault", "table:table_1")],
      scene,
    );
    expect(pts).toHaveLength(2);
    expect(pts[1].count).toBe(2);
  });

  test("skips steps whose item is not on the map", () => {
    const pts = pathPoints([step("street", "visitor"), step("vault", "table:missing")], scene);
    expect(pts).toHaveLength(1);
  });
});

describe("truncateLabel", () => {
  test("keeps short labels and ellipsizes long ones", () => {
    expect(truncateLabel("pets", 12)).toBe("pets");
    expect(truncateLabel("adoption_requests_archive", 12)).toBe("adoption_re…");
    expect(truncateLabel("adoption_requests_archive", 12)).toHaveLength(12);
  });
});

describe("reachedStops", () => {
  const line = [
    { x: 0, y: 0 },
    { x: 10, y: 0 },
    { x: 20, y: 0 },
  ];
  test("returns the stops covered by the drawn fraction", () => {
    expect(reachedStops(line, 0)).toHaveLength(1);
    expect(reachedStops(line, 0.5)).toHaveLength(2);
    expect(reachedStops(line, 0.49)).toHaveLength(1);
    expect(reachedStops(line, 1)).toHaveLength(3);
  });
});
