import { describe, expect, it } from "vitest";
import { EXAMPLES, shownExamples } from "./examples";

describe("examples", () => {
  it("lists the demo and clean apps and shows only entries with a URL", () => {
    expect(EXAMPLES.map((e) => e.label)).toEqual(["Demo app", "Clean app"]);
    expect(shownExamples()).toEqual([]);
    expect(shownExamples([{ label: "A", url: "https://github.com/a/b" }, { label: "B" }])).toEqual([
      { label: "A", url: "https://github.com/a/b" },
    ]);
  });
});
