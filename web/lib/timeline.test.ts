import { describe, expect, test } from "vitest";
import { WALK_SHARE, arrivalTime, buildTimeline, eventIndexAt, replaySteps, stepEventCount } from "./timeline";
import { cleanScene, provedFinding, vulnScene, worst } from "@/tests/helpers/scenes";
import { fixtureScene } from "@/tests/helpers/fixtureScene";

describe("buildTimeline", () => {
  test("ghost steps come before attack steps", () => {
    const t = buildTimeline(worst(vulnScene), vulnScene);
    const firstAttack = t.findIndex((e) => e.kind === "attack");
    expect(firstAttack).toBeGreaterThan(0);
    expect(t.slice(0, firstAttack).every((e) => e.kind === "ghost")).toBe(true);
  });

  test("replay lasts 20 to 30 seconds", () => {
    for (const f of [...vulnScene.findings, provedFinding]) {
      const end = buildTimeline(f, vulnScene).at(-1)!.at;
      expect(end).toBeGreaterThanOrEqual(20_000);
      expect(end).toBeLessThanOrEqual(30_000);
    }
    const clean = buildTimeline(null, cleanScene).at(-1)!.at;
    expect(clean).toBeGreaterThanOrEqual(20_000);
    expect(clean).toBeLessThanOrEqual(30_000);
  });

  test("proved findings end on the proof", () => {
    const t = buildTimeline(provedFinding, vulnScene);
    expect(t.at(-2)!.kind).toBe("proof");
    expect(t.at(-1)!.kind).toBe("end");
  });

  test("confirmed findings have no proof", () => {
    expect(buildTimeline(worst(vulnScene), vulnScene).some((e) => e.kind === "proof")).toBe(false);
  });

  test("clean app: every active door holds", () => {
    const t = buildTimeline(null, cleanScene);
    expect(t.filter((e) => e.kind === "lock-held").map((e) => e.zone)).toEqual([
      "guard_desk",
      "side_doors",
      "vault",
      "warehouse",
    ]);
  });

  test("clean app without database rules never claims the vault or warehouse locks", () => {
    const scene = { ...fixtureScene(), meta: { ...fixtureScene().meta, has_db_rules: false } };
    const t = buildTimeline(null, scene);
    expect(t.filter((e) => e.kind === "lock-held").map((e) => e.zone)).toEqual(["guard_desk", "side_doors"]);
  });

  test("clean app with migrations it could not read never claims the vault or warehouse locks", () => {
    const scene = { ...fixtureScene(), meta: { ...fixtureScene().meta, unparsed_migrations: ["a.sql"] } };
    const t = buildTimeline(null, scene);
    expect(t.filter((e) => e.kind === "lock-held").map((e) => e.zone)).toEqual(["guard_desk", "side_doors"]);
  });

  test("clean app with no door to try goes straight to the end", () => {
    const base = fixtureScene({ guard_desk: false, side_doors: false });
    const scene = { ...base, meta: { ...base.meta, has_db_rules: false } };
    expect(buildTimeline(null, scene)).toEqual([{ kind: "end", at: 0 }]);
  });

  test("clean app skips inactive doors", () => {
    const scene = fixtureScene({ side_doors: false, warehouse: false });
    const t = buildTimeline(null, scene);
    expect(t.filter((e) => e.kind === "lock-held").map((e) => e.zone)).toEqual(["guard_desk", "vault"]);
  });

  test("times start at 0, rise strictly and are whole ms", () => {
    const t = buildTimeline(provedFinding, vulnScene);
    expect(t[0].at).toBe(0);
    for (let i = 1; i < t.length; i++) expect(t[i].at).toBeGreaterThan(t[i - 1].at);
    expect(t.every((e) => Number.isInteger(e.at))).toBe(true);
  });

  test("keeps the base durations' proportions when scaling", () => {
    const f = worst(vulnScene)!;
    const t = buildTimeline(f, vulnScene);
    const ghost = t[1].at - t[0].at;
    const firstAttack = t.findIndex((e) => e.kind === "attack");
    const attack = t[firstAttack + 1].at - t[firstAttack].at;
    expect(attack / ghost).toBeCloseTo(2, 1);
  });

  test("step indices follow each path in order", () => {
    const f = worst(vulnScene)!;
    const t = buildTimeline(f, vulnScene);
    expect(t.filter((e) => e.kind === "ghost").map((e) => e.stepIndex)).toEqual(f.ghost_path.map((_, i) => i));
    expect(t.filter((e) => e.kind === "attack").map((e) => e.stepIndex)).toEqual(f.attack_path.map((_, i) => i));
  });

  test("deterministic", () => {
    expect(buildTimeline(provedFinding, vulnScene)).toEqual(buildTimeline(provedFinding, vulnScene));
  });
});

describe("replaySteps", () => {
  test("one step per step event, in timeline order", () => {
    const f = worst(vulnScene)!;
    const steps = replaySteps(f, vulnScene);
    const t = buildTimeline(f, vulnScene);
    expect(steps.length).toBe(stepEventCount(t));
    steps.forEach((s, i) => expect(s.kind).toBe(t[i].kind));
    expect(steps[0].step).toBe(f.ghost_path[0]);
    expect(steps.at(-1)!.step).toBe(f.attack_path.at(-1));
  });

  test("clean app: one plain step per door tried, on a real item of that zone", () => {
    const steps = replaySteps(null, cleanScene);
    expect(steps.map((s) => s.step.zone)).toEqual(["guard_desk", "side_doors", "vault", "warehouse"]);
    for (const s of steps) {
      const zone = cleanScene.zones.find((z) => z.id === s.step.zone)!;
      expect(zone.items.map((i) => i.node_id)).toContain(s.step.item_id);
      expect(s.step.story.length).toBeGreaterThan(0);
      expect(s.step.why.length).toBeGreaterThan(0);
      expect(s.step.ref).toBeNull();
    }
  });

  test("no em dash in any built copy", () => {
    const text = JSON.stringify(replaySteps(null, cleanScene));
    expect(text).not.toContain(String.fromCharCode(0x2014));
  });
});

describe("eventIndexAt", () => {
  test("finds the event running at a time", () => {
    const t = buildTimeline(worst(vulnScene), vulnScene);
    expect(eventIndexAt(t, 0)).toBe(0);
    expect(eventIndexAt(t, t[1].at - 1)).toBe(0);
    expect(eventIndexAt(t, t[1].at)).toBe(1);
    expect(eventIndexAt(t, 1e9)).toBe(t.length - 1);
  });
});

describe("arrivalTime", () => {
  test("lands inside the event, once the walk is done", () => {
    const t = buildTimeline(worst(vulnScene), vulnScene);
    for (let i = 0; i < t.length - 1; i++) {
      const a = arrivalTime(t, i);
      expect(eventIndexAt(t, a)).toBe(i);
      expect(a).toBe(t[i].at + Math.round((t[i + 1].at - t[i].at) * WALK_SHARE));
    }
    expect(arrivalTime(t, t.length - 1)).toBe(t.at(-1)!.at);
  });
});

describe("playerSteps", () => {
  test("proved findings get a final proof step the player can reach", async () => {
    const { playerSteps } = await import("./timeline");
    const steps = playerSteps(provedFinding, vulnScene);
    const t = buildTimeline(provedFinding, vulnScene);
    expect(steps).toHaveLength(t.length - 1);
    expect(steps.at(-1)!.kind).toBe("proof");
    expect(t[steps.length - 1].kind).toBe("proof");
    expect(steps.at(-1)!.step).toBe(provedFinding.attack_path.at(-1));
  });

  test("other findings and clean apps: just the path steps", async () => {
    const { playerSteps } = await import("./timeline");
    const f = worst(vulnScene)!;
    expect(playerSteps(f, vulnScene)).toEqual(replaySteps(f, vulnScene));
    expect(playerSteps(null, cleanScene)).toEqual(replaySteps(null, cleanScene));
  });
});
