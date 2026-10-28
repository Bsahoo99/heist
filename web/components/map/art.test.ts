import path from "node:path";
import { expect, test } from "vitest";
import { ART } from "./art.gen";
import { scanArt } from "@/scripts/gen-art-manifest.mjs";

test("art manifest matches public/art (run pnpm gen:art)", () => {
  expect(ART).toEqual(scanArt(path.resolve(__dirname, "../../public/art")));
});
