import { test as base, expect, type Page, type Browser } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

export const PASSWORD = "e2e-test-password-1";
export const SITE = "http://localhost:5273";
let n = 0;
export const uniqueEmail = (p = "u") => `${p}${Date.now()}-${++n}@example.com`;

/** Every test fails on console errors and on any 5xx response. */
export const test = base.extend<{ guard: void }>({
  guard: [async ({ page }, use) => {
    const problems: string[] = [];
    page.on("console", (m) => { if (m.type() === "error" && !/Failed to load resource.*status of (4\d\d|503)/.test(m.text())) problems.push(`console: ${m.text()}`); });
    page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
    page.on("response", (r) => { if (r.status() >= 500 && r.status() !== 503) problems.push(`${r.status()} ${r.url()}`); });
    await use();
    expect(problems, "console errors / 5xx during test").toEqual([]);
  }, { auto: true }],
});
export { expect };

export async function signUp(page: Page, email = uniqueEmail(), org = "E2E Org") {
  await page.goto("/signup");
  await page.getByLabel("Work email").fill(email);
  await page.getByLabel(/Organization name/).fill(org);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  return email;
}

export async function runSampleScan(page: Page) {
  await page.goto("/scans/new?sample=1");
  await page.getByRole("button", { name: "Run scan" }).click();
  await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
}

export async function a11y(page: Page, name: string) {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze();
  expect(r.violations.map((v) => `${name}: ${v.id} (${v.nodes.length}) ${v.help} :: ${v.nodes.slice(0, 2).map((n) => n.html.slice(0, 120) + ' | ' + (n.any[0]?.message ?? '').slice(0, 140)).join(' || ')}`), `axe violations on ${name}`).toEqual([]);
}

export async function newUserContext(browser: Browser) {
  const ctx = await browser.newContext({ baseURL: "http://localhost:5274" });
  return { ctx, page: await ctx.newPage() };
}
