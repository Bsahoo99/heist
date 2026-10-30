import { defineConfig, devices } from "@playwright/test";

// The e2e engine runs offline and copies local fixtures instead of cloning
// (engine/tests/e2e_server.py), so these tests never reach GitHub or a model.
const WEB_PORT = 3100;
const ENGINE_PORT = 8010;
const WEB_URL = `http://localhost:${WEB_PORT}`;
const ENGINE_URL = `http://127.0.0.1:${ENGINE_PORT}`;

export default defineConfig({
  testDir: "e2e",
  timeout: 150_000,
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  use: { baseURL: WEB_URL, trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 720 } } }],
  webServer: [
    {
      command: "uv run python -m tests.e2e_server",
      cwd: "../engine",
      url: `${ENGINE_URL}/openapi.json`,
      env: {
        HEIST_E2E_PORT: String(ENGINE_PORT),
        HEIST_WEB_ORIGINS: `${WEB_URL},http://127.0.0.1:${WEB_PORT}`,
        HEIST_E2E_DELAY: "1",
      },
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `pnpm exec next dev --port ${WEB_PORT}`,
      url: WEB_URL,
      env: { NEXT_PUBLIC_ENGINE_URL: ENGINE_URL },
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
});
