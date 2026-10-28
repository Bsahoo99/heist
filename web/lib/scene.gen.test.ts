import { readFileSync } from "node:fs";
import path from "node:path";
import { compileFromFile } from "json-schema-to-typescript";
import { expect, test } from "vitest";

const webRoot = path.resolve(__dirname, "..");

test("lib/scene.gen.ts is up to date with shared/scene.schema.json (run pnpm gen:scene)", async () => {
  const expected = await compileFromFile(path.join(webRoot, "../shared/scene.schema.json"), {
    cwd: path.join(webRoot, "../shared"),
  });
  const actual = readFileSync(path.join(webRoot, "lib/scene.gen.ts"), "utf8");
  expect(actual).toBe(expected);
});
