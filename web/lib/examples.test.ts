import { describe, expect, it } from "vitest";
import { EXAMPLES, shownExamples } from "./examples";

describe("examples", () => {
  it("links the demo and clean apps and shows only entries with a URL", () => {
    expect(EXAMPLES.map((e) => e.label)).toEqual(["Demo app", "Clean app"]);
    expect(shownExamples().map((e) => e.url)).toEqual([
      "https://github.com/Bsahoo99/pawhaven",
      "https://github.com/Bsahoo99/pawhaven-fixed",
    ]);
    expect(shownExamples([{ label: "A", url: "https://github.com/a/b" }, { label: "B" }])).toEqual([
      { label: "A", url: "https://github.com/a/b" },
    ]);
  });
});
