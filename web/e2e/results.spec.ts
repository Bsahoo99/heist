import { expect, test, type Page } from "@playwright/test";

// Stub repos served by engine/tests/e2e_server.py (offline, local fixtures).
const VULN_URL = "https://github.com/heist-fixtures/vuln-app";
const CLEAN_URL = "https://github.com/heist-fixtures/clean-app";
const NO_RULES_URL = "https://github.com/heist-fixtures/no-rules-app";
const ENGINE_URL = "http://127.0.0.1:8010";

/** Runs the heist on a stub repo and waits for the results; returns the analysis id. */
async function runHeist(page: Page, url: string): Promise<string> {
  await page.goto("/");
  await page.getByPlaceholder("https://github.com/you/your-app").fill(url);
  await page.getByRole("button", { name: "Run the heist" }).click();
  await expect(page).toHaveURL(/\/a\/[\w-]+$/);
  await expect(page.getByTestId("replay")).toHaveAttribute("data-state", "playing", { timeout: 60_000 });
  return new URL(page.url()).pathname.split("/").at(-1)!;
}

test("a clean run ends with the heist failing and offers the badge", async ({ page }) => {
  const id = await runHeist(page, CLEAN_URL);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Every lock held");

  // Skip to the last door, then let the replay play out to its end card.
  const map = page.getByRole("group", { name: /Heist replay/ });
  await map.focus();
  for (let i = 0; i < 6; i++) await map.press("ArrowRight");
  await map.press(" ");
  await expect(page.getByTestId("replay")).toHaveAttribute("data-state", "ended", { timeout: 15_000 });
  await expect(page.getByTestId("replay-end-title")).toHaveText("Your app held up against all seven checks.");

  const origin = new URL(page.url()).origin;
  await expect(page.getByRole("heading", { name: "Add the badge to your README" })).toBeVisible();
  await expect(page.getByTestId("badge-markdown")).toHaveText(
    `[![Heist-tested](${origin}/api/badge/${id})](${origin}/a/${id})`,
  );
  const img = page.getByRole("img", { name: "Heist-tested: 7/7 locks held" });
  await expect(img).toBeVisible();
  await expect.poll(() => img.evaluate((el: HTMLImageElement) => el.naturalWidth)).toBeGreaterThan(0);

  const badge = await page.request.get(`/api/badge/${id}`);
  expect(badge.status()).toBe(200);
  expect(badge.headers()["content-type"]).toBe("image/svg+xml; charset=utf-8");
  expect(badge.headers()["cache-control"]).toBe("public, max-age=3600");
  expect(await badge.text()).toContain("7/7 locks held");

  const missing = await page.request.get("/api/badge/not-a-real-id");
  expect(missing.status()).toBe(404);
  expect(missing.headers()["cache-control"]).toBe("no-store");
});

test("a repo without migrations shows the missing-rules card and its code findings", async ({ page }) => {
  await runHeist(page, NO_RULES_URL);
  await expect(page.getByRole("heading", { name: "We can't see your database rules" })).toBeVisible();
  await expect(page.getByTestId("check-sql")).toContainText("pg_policies");
  await expect(page.getByText("Paste this into the SQL editor in your Supabase dashboard.")).toBeVisible();
  await expect(page.getByTestId("finding-m1-vite-openai-api-key")).toBeVisible();
  await expect(page.getByTestId("finding-m2-src-lib-admin-ts")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Add the badge to your README" })).toHaveCount(0);
});

test.describe("with clipboard access", () => {
  test.use({ permissions: ["clipboard-read", "clipboard-write"] });

  test("a finding shows how to fix it and copies the fix prompt", async ({ page }) => {
    const id = await runHeist(page, VULN_URL);
    const analysis = await (await page.request.get(`${ENGINE_URL}/analyses/${id}`)).json();
    const first = analysis.scene.findings[0];

    await expect(page.getByRole("heading", { name: "How to fix it" })).toBeVisible();
    await expect(page.getByText(first.fix.explanation)).toBeVisible();
    await page.getByRole("button", { name: "Copy fix prompt" }).click();
    await expect(page.getByRole("button", { name: "Copied" })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(first.fix.prompt);
    await expect(page.getByRole("button", { name: "Copy fix prompt" })).toBeVisible({ timeout: 4_000 });
  });
});
