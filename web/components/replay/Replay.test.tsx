import { afterEach, describe, expect, test } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { motionValue } from "motion/react";
import { Replay } from "./Replay";
import type { ReplayClock } from "./useReplayClock";
import { buildTimeline } from "@/lib/timeline";
import type { Scene } from "@/lib/scene.gen";
import { cleanScene } from "@/tests/helpers/scenes";

afterEach(cleanup);

/** A clock parked on the end of the replay, not playing. */
function endedClock(scene: Scene): ReplayClock {
  const timeline = buildTimeline(null, scene);
  const end = timeline.at(-1)!.at;
  return {
    timeline,
    time: motionValue(end),
    eventIndex: timeline.length - 1,
    playing: false,
    setPlaying: () => {},
    seek: () => {},
  };
}

const withMeta = (meta: Partial<Scene["meta"]>): Scene => ({ ...cleanScene, meta: { ...cleanScene.meta, ...meta } });

function endCard(scene: Scene) {
  render(<Replay scene={scene} finding={null} clock={endedClock(scene)} />);
  return screen.getByRole("status");
}

describe("the clean end card", () => {
  test("every rule checked: the heist failed against all seven checks", () => {
    const card = endCard(cleanScene);
    expect(card.textContent).toContain("Heist failed");
    expect(screen.getByTestId("replay-end-title").textContent).toBe("Your app held up against all seven checks.");
    expect(card.textContent).toContain("Heist-tested: 7/7 locks held");
  });

  test("no rules: a neutral kicker and no claim about the database", () => {
    const card = endCard(withMeta({ has_db_rules: false, checks_tested: 5 }));
    expect(card.textContent).not.toContain("Heist failed");
    expect(card.textContent).toContain("Partly tested");
    expect(screen.getByTestId("replay-end-title").textContent).toBe("No way in through the code.");
    expect(card.textContent).not.toMatch(/all seven|locks held/);
  });

  test("migrations it could not read: says how many, no full verdict", () => {
    const card = endCard(withMeta({ unparsed_migrations: ["a.sql"] }));
    expect(card.textContent).not.toContain("Heist failed");
    expect(card.textContent).toContain("Partly tested");
    expect(card.textContent).not.toMatch(/all seven|every lock|locks held/i);
    expect(card.textContent).toContain("1 migration file could not be read, so the database checks may be incomplete.");
  });
});
