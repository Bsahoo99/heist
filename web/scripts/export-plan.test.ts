import { describe, expect, test } from "vitest";
import {
  DEFAULT_BASE,
  DEFAULT_ENGINE,
  gifArgs,
  mp4Args,
  paletteArgs,
  parseExportArgs,
  recordUrl,
  supabaseTarget,
  trimSeconds,
  uploadRequest,
} from "./export-plan.ts";

describe("parseExportArgs", () => {
  test("only --id: the local web app and engine, with upload", () => {
    expect(parseExportArgs(["--id", "abc_D-1"], {})).toEqual({
      id: "abc_D-1",
      base: DEFAULT_BASE,
      engine: DEFAULT_ENGINE,
      upload: true,
    });
  });

  test("--base, --engine and --no-upload; trailing slashes go; a leading -- from pnpm is fine", () => {
    const opts = parseExportArgs(
      ["--", "--id", "x", "--base", "https://heist.example/", "--engine", "http://127.0.0.1:8010/", "--no-upload"],
      {},
    );
    expect(opts).toEqual({ id: "x", base: "https://heist.example", engine: "http://127.0.0.1:8010", upload: false });
  });

  test("the engine comes from --engine, then HEIST_ENGINE_URL, then NEXT_PUBLIC_ENGINE_URL", () => {
    const env = { HEIST_ENGINE_URL: "http://server:1", NEXT_PUBLIC_ENGINE_URL: "http://browser:2" };
    expect(parseExportArgs(["--id", "x", "--engine", "http://flag:3"], env).engine).toBe("http://flag:3");
    expect(parseExportArgs(["--id", "x"], env).engine).toBe("http://server:1");
    expect(parseExportArgs(["--id", "x"], { NEXT_PUBLIC_ENGINE_URL: "http://browser:2" }).engine).toBe("http://browser:2");
    // An empty variable (as in .env.example) means the local engine.
    expect(parseExportArgs(["--id", "x"], { HEIST_ENGINE_URL: "", NEXT_PUBLIC_ENGINE_URL: "" }).engine).toBe(
      DEFAULT_ENGINE,
    );
  });

  test.each([
    [[]],
    [["--id", ""]],
    [["--id", "../etc/passwd"]],
    [["--id", "a b"]],
    [["--id", "a".repeat(65)]],
  ])("refuses a missing or bad id: %j", (argv) => {
    expect(() => parseExportArgs(argv, {})).toThrow(/--id must be an analysis id/);
  });

  test("refuses unknown options, stray words and non-http URLs", () => {
    expect(() => parseExportArgs(["--id", "x", "--force"], {})).toThrow();
    expect(() => parseExportArgs(["--id", "x", "extra"], {})).toThrow();
    expect(() => parseExportArgs(["--id", "x", "--base", "file:///tmp"], {})).toThrow("--base must be an http(s) URL.");
    expect(() => parseExportArgs(["--id", "x", "--engine", "nope"], {})).toThrow("--engine must be an http(s) URL.");
  });
});

test("recordUrl opens record mode", () => {
  expect(recordUrl("http://localhost:3000", "abc")).toBe("http://localhost:3000/a/abc?record=1");
});

test("trimSeconds cuts the page load, never a negative amount", () => {
  expect(trimSeconds(1_000, 3_456)).toBe(2.456);
  expect(trimSeconds(5_000, 4_000)).toBe(0);
  expect(trimSeconds(0, 1_234.6)).toBe(1.235);
});

describe("ffmpeg arguments", () => {
  test("MP4: trimmed, H.264, yuv420p, 30 fps, faststart, no audio", () => {
    const args = mp4Args("in.webm", 2.5, "out.mp4");
    expect(args.slice(args.indexOf("-ss"), args.indexOf("-ss") + 4)).toEqual(["-ss", "2.500", "-i", "in.webm"]);
    const pairs = Object.fromEntries(args.map((a, i) => [a, args[i + 1]]));
    expect(pairs["-c:v"]).toBe("libx264");
    expect(pairs["-pix_fmt"]).toBe("yuv420p");
    expect(pairs["-r"]).toBe("30");
    expect(pairs["-movflags"]).toBe("+faststart");
    expect(args).toContain("-an");
    expect(args.at(-1)).toBe("out.mp4");
  });

  test("GIF: a palette pass, then 720 px wide at 12 fps with that palette", () => {
    const palette = paletteArgs("out.mp4", "palette.png");
    expect(palette.slice(-3)).toEqual(["-vf", "fps=12,scale=720:-1:flags=lanczos,palettegen=stats_mode=diff", "palette.png"]);
    const gif = gifArgs("out.mp4", "palette.png", "out.gif");
    expect(gif.slice(gif.indexOf("-i"), gif.indexOf("-i") + 4)).toEqual(["-i", "out.mp4", "-i", "palette.png"]);
    expect(gif[gif.indexOf("-lavfi") + 1]).toMatch(/^fps=12,scale=720:-1:flags=lanczos\[x\];\[x\]\[1:v\]paletteuse=/);
    expect(gif.at(-1)).toBe("out.gif");
  });
});

describe("supabaseTarget", () => {
  test("the shell's variables first, then the engine's file, only the two names", () => {
    const file = { SUPABASE_URL: "https://file.supabase.co/", SUPABASE_SERVICE_ROLE_KEY: "file-key", OTHER: "x" };
    expect(supabaseTarget({}, file)).toEqual({ url: "https://file.supabase.co", key: "file-key" });
    expect(supabaseTarget({ SUPABASE_URL: "https://shell.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "shell-key" }, file)).toEqual({
      url: "https://shell.supabase.co",
      key: "shell-key",
    });
  });

  test("missing values say how to skip the upload, without echoing anything", () => {
    expect(() => supabaseTarget({ SUPABASE_SERVICE_ROLE_KEY: "only-key" }, {})).toThrow(/--no-upload/);
    const bad = () => supabaseTarget({ SUPABASE_URL: "not a url", SUPABASE_SERVICE_ROLE_KEY: "sb_secret_abc" }, {});
    expect(bad).toThrow("SUPABASE_URL must be an http(s) URL.");
  });
});

describe("uploadRequest", () => {
  test("upserts into the private exports bucket with the key in apikey only", () => {
    const req = uploadRequest({ url: "https://p.supabase.co", key: "sb_secret_abc" }, "id1", "mp4");
    expect(req.url).toBe("https://p.supabase.co/storage/v1/object/exports/id1.mp4");
    expect(req.headers).toEqual({ apikey: "sb_secret_abc", "Content-Type": "video/mp4", "x-upsert": "true" });
  });

  test("a legacy JWT key is also the bearer token", () => {
    const req = uploadRequest({ url: "https://p.supabase.co", key: "eyJhbGciOi.x.y" }, "id1", "gif");
    expect(req.headers.Authorization).toBe("Bearer eyJhbGciOi.x.y");
    expect(req.headers["Content-Type"]).toBe("image/gif");
    expect(uploadRequest({ url: "https://p.supabase.co", key: "k" }, "id1", "png").headers["Content-Type"]).toBe(
      "image/png",
    );
  });
});
