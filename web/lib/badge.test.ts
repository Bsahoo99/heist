import { describe, expect, test } from "vitest";
import { badgeMarkdown, badgeSvg, badgeText, badgeTone, offersBadge } from "./badge";
import { cleanScene, vulnScene } from "@/tests/helpers/scenes";
import type { Scene } from "./scene.gen";

const withMeta = (scene: Scene, meta: Partial<Scene["meta"]>): Scene => ({ ...scene, meta: { ...scene.meta, ...meta } });

describe("badgeText", () => {
  test("clean badge text", () => {
    expect(badgeText(cleanScene)).toBe("Heist-tested: 7/7 locks held");
  });

  test("failing badge counts held checks", () => {
    expect(badgeText(vulnScene)).toBe(`Heist-tested: ${vulnScene.meta.checks_held}/7 locks held`);
  });

  test("never claims locks it could not test", () => {
    expect(badgeText(withMeta(cleanScene, { has_db_rules: false }))).toBe("Heist-tested: database rules not checked");
  });
});

describe("badgeTone", () => {
  test.each([
    [7, "green"],
    [6, "amber"],
    [5, "amber"],
    [4, "red"],
    [0, "red"],
  ] as const)("%i/7 is %s", (held, tone) => {
    expect(badgeTone(withMeta(cleanScene, { checks_held: held }))).toBe(tone);
  });

  test("rules not checked is grey", () => {
    expect(badgeTone(withMeta(cleanScene, { has_db_rules: false }))).toBe("grey");
  });
});

describe("offersBadge", () => {
  test("only when every check held and the rules were seen", () => {
    expect(offersBadge(cleanScene)).toBe(true);
    expect(offersBadge(vulnScene)).toBe(false);
    expect(offersBadge(withMeta(cleanScene, { has_db_rules: false }))).toBe(false);
  });
});

describe("badgeSvg", () => {
  test("a two-part badge with the full text as its title", () => {
    const svg = badgeSvg("Heist-tested: 7/7 locks held", "green");
    expect(svg.startsWith("<svg ")).toBe(true);
    expect(svg).toContain('role="img"');
    expect(svg).toContain('aria-label="Heist-tested: 7/7 locks held"');
    expect(svg).toContain("<title>Heist-tested: 7/7 locks held</title>");
    expect(svg).toContain(">Heist-tested</text>");
    expect(svg).toContain(">7/7 locks held</text>");
  });

  test("each tone has its own colour", () => {
    const fills = (["green", "amber", "red", "grey"] as const).map((t) => badgeSvg("Heist-tested: x", t));
    expect(new Set(fills).size).toBe(4);
  });

  test("escapes XML", () => {
    const svg = badgeSvg(`Heist-tested: <a & "b" 'c'>`, "red");
    expect(svg).not.toContain("<a ");
    expect(svg).toContain("&lt;a &amp; &quot;b&quot; &apos;c&apos;&gt;");
  });

  test("the right part grows with its text", () => {
    const width = (s: string) => Number(/^<svg [^>]*width="(\d+)"/.exec(s)?.[1]);
    expect(width(badgeSvg("Heist-tested: database rules not checked", "grey"))).toBeGreaterThan(
      width(badgeSvg("Heist-tested: 7/7 locks held", "green")),
    );
  });
});

test("badgeMarkdown links the badge to the analysis", () => {
  expect(badgeMarkdown("https://heist.example", "abc123")).toBe(
    "[![Heist-tested](https://heist.example/api/badge/abc123)](https://heist.example/a/abc123)",
  );
});
