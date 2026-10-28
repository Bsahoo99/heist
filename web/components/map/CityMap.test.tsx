import { afterEach, describe, expect, test } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { CityMap } from "./CityMap";
import { fixtureScene } from "@/tests/helpers/fixtureScene";
import type { PathStep, Scene, Zone as ZoneId } from "@/lib/scene.gen";
import vulnJson from "@/tests/fixtures/vuln-scene.json";
import cleanJson from "@/tests/fixtures/clean-scene.json";

const vulnScene = vulnJson as unknown as Scene;
const cleanScene = cleanJson as unknown as Scene;

afterEach(cleanup);

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

const points = (el: Element) =>
  (el.getAttribute("points") ?? "").trim().split(/\s+/).filter(Boolean);

describe("CityMap zones", () => {
  test("inactive zones render greyed", () => {
    render(<CityMap scene={fixtureScene({ warehouse: false })} />);
    const zone = screen.getByTestId("zone-warehouse");
    expect(zone.getAttribute("data-active")).toBe("false");
    expect(zone.textContent).toContain("Not used by this app");
    expect(screen.getByTestId("zone-vault").getAttribute("data-active")).toBe("true");
  });

  test("renders all seven zones", () => {
    render(<CityMap scene={cleanScene} />);
    for (const id of [
      "street",
      "shop_window",
      "guard_desk",
      "side_doors",
      "vault",
      "warehouse",
      "across_road",
    ]) {
      expect(screen.getByTestId(`zone-${id}`)).toBeTruthy();
    }
  });
});

describe("CityMap items", () => {
  test("one vault box per table", () => {
    render(<CityMap scene={vulnScene} />);
    expect(screen.getAllByTestId(/^item-table:/)).toHaveLength(5);
  });

  test("street and guard desk have single items", () => {
    render(<CityMap scene={vulnScene} />);
    expect(screen.getAllByTestId("item-visitor")).toHaveLength(1);
    expect(screen.getAllByTestId("item-auth:supabase")).toHaveLength(1);
  });

  test("flagged items are marked", () => {
    render(<CityMap scene={vulnScene} />);
    expect(screen.getByTestId("item-table:messages").getAttribute("data-flagged")).toBe("true");
    expect(screen.getByTestId("item-table:notes").getAttribute("data-flagged")).toBe("false");
  });

  test("overflow puts extras behind the last slot with a +N label", () => {
    render(<CityMap scene={fixtureScene({ tables: 15 })} />);
    expect(screen.getAllByTestId(/^item-table:/)).toHaveLength(15);
    expect(screen.getByTestId("overflow-vault").textContent).toBe("+3");
  });

  test("long labels truncate and keep the full name in a title", () => {
    const long = "customer_support_conversations";
    render(<CityMap scene={fixtureScene({ tableLabels: [long] })} />);
    const label = screen.getByTestId(`label-table:${long}`);
    expect(label.querySelector("title")?.textContent).toBe(long);
    expect(label.querySelector("text")?.textContent).toMatch(/…$/);
  });

  test("highlight marks the item and zone", () => {
    render(<CityMap scene={vulnScene} highlight={{ nodeId: "table:pets", zone: "vault" }} />);
    expect(screen.getByTestId("item-table:pets").getAttribute("data-highlighted")).toBe("true");
    expect(screen.getByTestId("item-table:notes").getAttribute("data-highlighted")).toBe("false");
    expect(screen.getByTestId("zone-vault").getAttribute("data-highlighted")).toBe("true");
  });
});

describe("CityMap accessibility and determinism", () => {
  test("svg has role img, a title and a summary label", () => {
    render(<CityMap scene={fixtureScene({ warehouse: false, across_road: false })} />);
    const svg = screen.getByRole("img");
    expect(svg.querySelector(":scope > title")?.textContent).toBeTruthy();
    const label = svg.getAttribute("aria-label") ?? "";
    expect(label).toContain("Vault");
    expect(label).not.toContain("Warehouse");
    expect(label).toContain("1 flagged item");
  });

  test("same scene renders the same svg", () => {
    const a = render(<CityMap scene={vulnScene} />).container.innerHTML;
    cleanup();
    const b = render(<CityMap scene={vulnScene} />).container.innerHTML;
    expect(a).toBe(b);
  });
});

describe("CityMap paths", () => {
  const scene = fixtureScene({ tables: 3 });
  const ghost = [step("street", "visitor"), step("guard_desk", "auth:supabase"), step("vault", "table:table_2")];
  const attack = [
    step("street", "visitor"),
    step("side_doors", "fn:hello"),
    step("vault", "table:table_1"),
    step("vault", "table:table_1"),
  ];

  test("draws ghost and attack lines through each item", () => {
    render(<CityMap scene={scene} ghost={ghost} attack={attack} />);
    expect(points(screen.getByTestId("path-ghost"))).toHaveLength(3);
    // The repeated last step stacks: 3 distinct points, no zero-length segment.
    const pts = points(screen.getByTestId("path-attack"));
    expect(pts).toHaveLength(3);
    expect(new Set(pts).size).toBe(pts.length);
  });

  test("progress draws a partial attack line by length", () => {
    render(<CityMap scene={scene} attack={attack} progress={0.5} />);
    const el = screen.getByTestId("path-attack");
    const total = Number(el.getAttribute("data-total-length"));
    const drawn = Number(el.getAttribute("data-drawn-length"));
    expect(total).toBeGreaterThan(0);
    expect(drawn).toBeCloseTo(total / 2, 1);
  });

  test("progress 0 draws no attack line", () => {
    render(<CityMap scene={scene} attack={attack} progress={0} />);
    expect(points(screen.getByTestId("path-attack"))).toHaveLength(0);
  });
});
