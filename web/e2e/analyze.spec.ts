import { expect, test } from "@playwright/test";

// Stub repos served by engine/tests/e2e_server.py (copied from the engine's test fixtures).
const STUB_URL = "https://github.com/heist-fixtures/vuln-app";
const UNSUPPORTED_URL = "https://github.com/heist-fixtures/plain-vite";

const BAD_URL_COPY = "Paste a public GitHub repo URL, like https://github.com/you/your-app.";
const UNSUPPORTED_COPY =
  "Heist supports Vite + React + Supabase and Next.js + Supabase apps. This stack is not supported yet.";

test("paste url, map builds, replay starts", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveTitle("Heist");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "See how your vibe-coded app gets robbed, before someone else does.",
  );
  await page.getByPlaceholder("https://github.com/you/your-app").fill(STUB_URL);
  await page.getByRole("button", { name: "Run the heist" }).click();
  await expect(page).toHaveURL(/\/a\/[\w-]+$/);
  // The live map lights up while the engine works.
  await expect(page.getByTestId("live-stage")).toBeVisible();
  await expect(page.getByTestId("zone-vault")).toHaveAttribute("data-active", "true");
  await expect(page.getByTestId("replay")).toHaveAttribute("data-state", "playing", { timeout: 120_000 });
  await expect(page.getByRole("heading", { name: /All findings/ })).toBeVisible();
});

test("reloading mid-run picks the analysis up again", async ({ page }) => {
  await page.goto("/");
  await page.getByPlaceholder("https://github.com/you/your-app").fill(STUB_URL);
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("zone-vault")).toHaveAttribute("data-active", "true");
  await page.reload();
  await expect(page.getByTestId("replay")).toHaveAttribute("data-state", "playing", { timeout: 120_000 });
});

test("a non-GitHub URL shows the reason under the input", async ({ page }) => {
  await page.goto("/");
  await page.getByPlaceholder("https://github.com/you/your-app").fill("https://gitlab.com/a/b");
  await page.getByRole("button", { name: "Run the heist" }).click();
  await expect(page.getByText(BAD_URL_COPY)).toBeVisible();
  await expect(page).toHaveURL("/");
});

test("an unsupported repo ends in a plain error with a way back", async ({ page }) => {
  await page.goto("/");
  await page.getByPlaceholder("https://github.com/you/your-app").fill(UNSUPPORTED_URL);
  await page.getByRole("button", { name: "Run the heist" }).click();
  await expect(page.getByText(UNSUPPORTED_COPY)).toBeVisible({ timeout: 30_000 });
  await page.getByRole("link", { name: "Try another repo" }).click();
  await expect(page).toHaveURL("/");
  // The landing page Next kept alive is ready for the next repo.
  await expect(page.getByRole("button", { name: "Run the heist" })).toBeEnabled();
});

test("an unknown analysis says it is gone", async ({ page }) => {
  await page.goto("/a/not-a-real-id");
  await expect(page.getByText("This analysis is gone. Run it again.")).toBeVisible();
  await expect(page.getByRole("link", { name: "Try another repo" })).toBeVisible();
});
