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

  test("inactiveNote null leaves inactive zones unlabelled", () => {
    render(<CityMap scene={fixtureScene({ warehouse: false })} inactiveNote={null} />);
    const zone = screen.getByTestId("zone-warehouse");
    expect(zone.getAttribute("data-active")).toBe("false");
    expect(zone.textContent).not.toContain("Not used by this app");
  });

  test("testIds false drops the whole-block test ids", () => {
    render(<CityMap scene={cleanScene} testIds={false} />);
    expect(screen.queryByTestId("zone-vault")).toBeNull();
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
  test("each svg has role img, a title and a summary label", () => {
    render(<CityMap scene={fixtureScene({ warehouse: false, across_road: false })} />);
    const svgs = screen.getAllByRole("img");
    expect(svgs).toHaveLength(2); // the full block and the narrow-screen framing
    for (const svg of svgs) {
      expect(svg.querySelector(":scope > title")?.textContent).toBeTruthy();
      const label = svg.getAttribute("aria-label") ?? "";
      expect(label).toContain("Vault");
      expect(label).not.toContain("Warehouse");
      expect(label).toContain("1 flagged item");
    }
  });

  test("same scene renders the same svg", () => {
    const finding = vulnScene.findings[0];
    const el = <CityMap scene={vulnScene} ghost={finding.ghost_path} attack={finding.attack_path} progress={0.4} />;
    const a = render(el).container.innerHTML;
    cleanup();
    const b = render(el).container.innerHTML;
    expect(a).toBe(b);
  });

  test("zone titles paint above the paths", () => {
    const finding = vulnScene.findings[0];
    const { container } = render(
      <CityMap scene={vulnScene} ghost={finding.ghost_path} attack={finding.attack_path} />,
    );
    const full = container.querySelector(".citymap-full svg")!;
    const children = [...full.children];
    const paths = children.findIndex((c) => c.getAttribute("data-testid") === "paths");
    const labels = children.findIndex((c) => c.getAttribute("data-testid") === "labels");
    expect(paths).toBeGreaterThan(-1);
    expect(labels).toBeGreaterThan(paths);
    expect(children[labels].querySelector('[data-zone-title="vault"]')?.textContent).toBe("Vault");
  });
});

describe("CityMap narrow framing", () => {
  test("the focus map labels only the items on the path and has a whole-map toggle", () => {
    const finding = vulnScene.findings.find((f) => f.id === "m1-vite-openai-api-key")!;
    const { container } = render(
      <CityMap scene={vulnScene} ghost={finding.ghost_path} attack={finding.attack_path} />,
    );
    const focus = container.querySelector(".citymap-focus svg")!;
    const full = container.querySelector(".citymap-full svg")!;
    expect(focus.getAttribute("viewBox")).not.toBe(full.getAttribute("viewBox"));
    const focusLabels = [...focus.querySelectorAll("title")].slice(1).map((t) => t.textContent);
    expect(focusLabels).toContain("Visitor");
    expect(focusLabels).toContain("api.openai.com");
    const allowed = new Set([...finding.ghost_path, ...finding.attack_path].map((st) => st.item_id));
    const byLabel = new Map(vulnScene.zones.flatMap((z) => z.items.map((i) => [i.label, i.node_id])));
    for (const l of focusLabels) expect(allowed.has(byLabel.get(l ?? "") ?? ""), l ?? "").toBe(true);
    expect(focusLabels).not.toContain("Upload.tsx"); // not on the path
    expect(focusLabels).not.toContain("messages"); // flagged, but not on this path
    expect(screen.getByLabelText("Show whole map")).toBeTruthy();
  });

  test("the focus map drops labels and titles that would be clipped by its frame", () => {
    const finding = vulnScene.findings.find((f) => f.id === "m5-send-email")!;
    const { container } = render(
      <CityMap scene={vulnScene} ghost={finding.ghost_path} attack={finding.attack_path} />,
    );
    const focus = container.querySelector(".citymap-focus svg")!;
    const [x, y, w, h] = (focus.getAttribute("viewBox") ?? "").split(" ").map(Number);
    for (const rect of focus.querySelectorAll("g > rect[rx]")) {
      const rx = Number(rect.getAttribute("x"));
      const ry = Number(rect.getAttribute("y"));
      expect(rx).toBeGreaterThanOrEqual(x);
      expect(ry).toBeGreaterThanOrEqual(y);
      expect(rx + Number(rect.getAttribute("width"))).toBeLessThanOrEqual(x + w + 0.01);
      expect(ry + Number(rect.getAttribute("height"))).toBeLessThanOrEqual(y + h + 0.01);
    }
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

  test("draws ghost and attack routes with a stop on each item", () => {
    render(<CityMap scene={scene} ghost={ghost} attack={attack} />);
    expect(screen.getAllByTestId("stop-ghost")).toHaveLength(3);
    // The repeated last step stacks into one stop with a count of 2.
    const stops = screen.getAllByTestId("stop-attack");
    expect(stops).toHaveLength(3);
    expect(stops[2].getAttribute("data-count")).toBe("2");
    const pts = points(screen.getByTestId("path-attack"));
    for (let i = 1; i < pts.length; i++) expect(pts[i]).not.toBe(pts[i - 1]);
  });

  test("identical ghost and attack routes are drawn apart", () => {
    render(<CityMap scene={scene} ghost={ghost} attack={ghost} />);
    const g = points(screen.getByTestId("path-ghost"));
    const a = points(screen.getByTestId("path-attack"));
    expect(g).toHaveLength(a.length);
    g.forEach((p, i) => expect(p).not.toBe(a[i]));
  });

  test("progress draws a partial attack line by length", () => {
    render(<CityMap scene={scene} attack={attack} progress={0.5} />);
    const el = screen.getByTestId("path-attack");
    const total = Number(el.getAttribute("data-total-length"));
    const drawn = Number(el.getAttribute("data-drawn-length"));
    expect(total).toBeGreaterThan(0);
    expect(drawn).toBeCloseTo(total / 2, 1);
    expect(screen.getAllByTestId("stop-attack").length).toBeLessThan(3);
  });

  test("progress 0 draws no attack line", () => {
    render(<CityMap scene={scene} attack={attack} progress={0} />);
    expect(points(screen.getByTestId("path-attack"))).toHaveLength(0);
    expect(screen.queryAllByTestId("stop-attack")).toHaveLength(0);
  });
});
