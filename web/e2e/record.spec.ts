import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

// Record mode (`/a/<id>?record=1`): what `pnpm export` films. Stub repos are
// served by engine/tests/e2e_server.py (offline, local fixtures).
const VULN_URL = "https://github.com/heist-fixtures/vuln-app";
const CLEAN_URL = "https://github.com/heist-fixtures/clean-app";
const ENGINE_URL = "http://127.0.0.1:8010";

test.use({ viewport: { width: 1280, height: 720 } });

/** Starts an analysis on the engine and waits until it is done; returns its id. */
async function analyze(request: APIRequestContext, url: string): Promise<string> {
  const res = await request.post(`${ENGINE_URL}/analyses`, { data: { url } });
  expect(res.ok()).toBe(true);
  const { id } = (await res.json()) as { id: string };
  await expect
    .poll(async () => (await (await request.get(`${ENGINE_URL}/analyses/${id}`)).json()).status, {
      timeout: 60_000,
    })
    .toBe("done");
  return id;
}

/** Only the map and the caption, the map inside the viewport, and nothing to scroll. */
async function expectRecordFrame(page: Page) {
  await expect(page.getByTestId("replay")).toBeVisible();
  await expect(page.locator(".replay-caption")).toBeVisible();
  await expect(page.getByTestId("findings-list")).toHaveCount(0);
  await expect(page.locator(".site-bar")).toHaveCount(0);
  await expect(page.locator(".results-head")).toHaveCount(0);
  await expect(page.getByRole("group", { name: "Step player" })).toHaveCount(0);
  await expect(page.locator(".badge-block")).toHaveCount(0);
  await expect(page.locator(".export-links")).toHaveCount(0);
  const map = await page.locator(".replay-map .citymap-wide").boundingBox();
  expect(map).not.toBeNull();
  expect(map!.y).toBeGreaterThanOrEqual(0);
  expect(map!.y + map!.height).toBeLessThanOrEqual(720);
  expect(map!.x + map!.width).toBeLessThanOrEqual(1280);
  const scroll = await page.evaluate(() => ({
    h: document.documentElement.scrollHeight,
    w: document.documentElement.scrollWidth,
  }));
  expect(scroll.h).toBeLessThanOrEqual(720);
  expect(scroll.w).toBeLessThanOrEqual(1280);
}

test("record mode finishes within 32s and hides chrome", async ({ page, request }) => {
  const id = await analyze(request, VULN_URL);
  await page.goto(`/a/${id}?record=1`);
  await expect(page.locator("body")).toHaveAttribute("data-started", /^\d{13}$/, { timeout: 15_000 });
  await expectRecordFrame(page);
  await expect(page.locator("body")).toHaveAttribute("data-done", "true", { timeout: 32_000 });
  // The end card stays in the frame, without the player's buttons.
  await expect(page.getByTestId("replay-end-title")).toBeVisible();
  await expect(page.getByRole("button", { name: "Watch again" })).toHaveCount(0);
});

test("record mode replays a clean run's locks and ends the same way", async ({ page, request }) => {
  const id = await analyze(request, CLEAN_URL);
  await page.goto(`/a/${id}?record=1`);
  await expect(page.locator("body")).toHaveAttribute("data-started", /^\d{13}$/, { timeout: 15_000 });
  await expectRecordFrame(page);
  await expect(page.getByTestId("replay")).toHaveAttribute("data-phase", "lock-held", { timeout: 15_000 });
  await expect(page.locator("body")).toHaveAttribute("data-done", "true", { timeout: 32_000 });
  await expect(page.getByTestId("replay-end-title")).toHaveText("Your app held up against all seven checks.");
});

test("the share card is a PNG cached briefly until a poster exists", async ({ request }) => {
  const id = await analyze(request, VULN_URL);
  for (const path of [`/a/${id}/opengraph-image`, "/a/not-a-real-id/opengraph-image"]) {
    const res = await request.get(path);
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toBe("image/png");
    // The e2e engine keeps no exports, so this is the fallback frame's short cache, never immutable.
    expect(res.headers()["cache-control"]).toBe("public, max-age=300");
  }
});

test("record mode of an unknown analysis fails at once", async ({ page }) => {
  await page.goto("/a/not-a-real-id?record=1");
  await expect(page.locator("body")).toHaveAttribute("data-done", "failed", { timeout: 10_000 });
});
