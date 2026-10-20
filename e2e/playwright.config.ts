import { defineConfig } from "@playwright/test";

// Isolated ports and an in-memory database, so this never touches a dev server or dev data.
const API = 8090, APP = 5274, SITE = 5273;
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  reporter: [["list"]],
  use: { channel: "chrome", baseURL: `http://localhost:${APP}`, trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "desktop", use: { viewport: { width: 1280, height: 800 } }, grepInvert: /@mobile/ }, { name: "mobile", use: { viewport: { width: 390, height: 800 } }, grep: /@mobile/ }],
  webServer: [
    {
      command: "npx tsx test/support/e2e-server.ts", cwd: "../artifacts/api-server", url: `http://localhost:${API}/api/healthz`, reuseExistingServer: false, timeout: 60_000,
      env: { PORT: String(API), DATA_DIR: ":memory:", NODE_ENV: "development", RATE_LIMIT_DISABLED: "1", JWT_SECRET: "e2e-secret", SSO_SECRET: "e2e-sso-secret-with-at-least-32-characters",
        APP_ORIGINS: `http://localhost:${APP},http://localhost:${SITE}`, APP_URL: `http://localhost:${APP}` },
    },
    { command: "npx vite", cwd: "../artifacts/cspm-app", url: `http://localhost:${APP}`, reuseExistingServer: false, env: { PORT: String(APP), API_PROXY: `http://localhost:${API}` } },
    { command: "npx vite", cwd: "../artifacts/cspm-site", url: `http://localhost:${SITE}`, reuseExistingServer: false, env: { PORT: String(SITE), API_PROXY: `http://localhost:${API}`, VITE_APP_URL: `http://localhost:${APP}` } },
  ],
});
