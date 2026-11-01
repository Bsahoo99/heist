import { describe, expect, test } from "vitest";
import { cleanScene, vulnScene } from "@/tests/helpers/scenes";
import type { Scene } from "./scene.gen";
import { repoName, shareCard, shareTitle, TAGLINE } from "./share";

const withMeta = (scene: Scene, meta: Partial<Scene["meta"]>): Scene => ({ ...scene, meta: { ...scene.meta, ...meta } });

test("repoName keeps owner/name of a GitHub URL only", () => {
  expect(repoName("https://github.com/acme/pawpal")).toBe("acme/pawpal");
  expect(repoName("https://github.com/acme/pawpal/")).toBe("acme/pawpal");
  expect(repoName("https://gitlab.com/acme/pawpal")).toBeNull();
  expect(repoName("https://github.com/acme")).toBeNull();
  expect(repoName(null)).toBeNull();
});

test("shareTitle names the repo when known", () => {
  expect(shareTitle("acme/pawpal")).toBe("Heist: acme/pawpal");
  expect(shareTitle(null)).toBe("Heist");
});

describe("shareCard", () => {
  test("no finished analysis: the tagline", () => {
    expect(shareCard(null)).toEqual({ headline: TAGLINE, note: null });
  });

  test("findings: the worst one, its status and how many more", () => {
    const card = shareCard(vulnScene);
    const worst = vulnScene.findings[0];
    expect(card.headline).toBe(worst.title);
    const more = vulnScene.findings.length - 1;
    expect(card.note).toBe(`Confirmed. ${more} more findings`);
    const one = { ...vulnScene, findings: [{ ...worst, status: "possible" as const }] };
    expect(shareCard(one).note).toBe("Possible, not confirmed");
    const two = { ...vulnScene, findings: [{ ...worst, status: "proved" as const }, worst] };
    expect(shareCard(two).note).toBe("Proved. 1 more finding");
  });

  test("clean: locks held only when every rule was read", () => {
    expect(shareCard(cleanScene)).toMatchObject({ headline: "7/7 locks held" });
    const partial = withMeta(cleanScene, { unparsed_migrations: ["a.sql"] });
    expect(shareCard(partial)).toEqual({
      headline: "No way in found",
      note: "1 migration file could not be read, so the database checks may be incomplete.",
    });
    const none = withMeta(cleanScene, { has_db_rules: false });
    expect(shareCard(none)).toMatchObject({ headline: "No way in through the code" });
    expect(JSON.stringify(shareCard(none))).not.toMatch(/locks held/);
  });
});
