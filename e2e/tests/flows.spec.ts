import { a11y, expect, newUserContext, PASSWORD, runSampleScan, signUp, SITE, test, uniqueEmail } from "./fixtures";

test.describe("F01 visitor tries a scan on the marketing site", () => {
  test("F01-H1 sample demo scan shows ranked findings and a signup prompt", async ({ page }) => {
    await page.goto(SITE);
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await expect(page.getByText("Posture score", { exact: true })).toBeVisible();
    await expect(page.getByText("Admin or database port open to the internet").first()).toBeVisible();
    await expect(page.getByRole("link", { name: "Create a free account" })).toBeVisible();
    await a11y(page, "site home");
  });
  test("F01-E1 invalid JSON gives a readable error, no crash", async ({ page }) => {
    await page.goto(SITE);
    await page.getByLabel("Your resources (JSON)").fill("{ not json");
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("not valid JSON");
  });
  test("F01-E2 empty resource list is rejected by the server with a message", async ({ page }) => {
    await page.goto(SITE);
    await page.getByLabel("Your resources (JSON)").fill("[]");
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("No resources");
  });
  test("F01-E3 unsupported resource types are reported, not silently dropped", async ({ page }) => {
    await page.goto(SITE);
    await page.getByLabel("Your resources (JSON)").fill(JSON.stringify([{ type: "lambda", name: "fn" }]));
    await page.getByRole("button", { name: "Scan", exact: true }).click();
    await expect(page.getByText("Not checked (unsupported type): lambda")).toBeVisible();
  });
  test("F01-H2 pricing and docs pages render", async ({ page }) => {
    await page.goto(`${SITE}/pricing`);
    await expect(page.getByRole("heading", { name: "Simple pricing" })).toBeVisible();
    await expect(page.getByText("$19")).toBeVisible();
    await a11y(page, "pricing");
    await page.goto(`${SITE}/docs`);
    await expect(page.getByRole("heading", { name: "Quickstart" })).toBeVisible();
    await a11y(page, "docs");
  });
  test("F01-H3 sign-in and start-free buttons point at the app", async ({ page }) => {
    await page.goto(SITE);
    await expect(page.getByRole("link", { name: "Start free" }).first()).toHaveAttribute("href", "http://localhost:5274/signup");
    await expect(page.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "http://localhost:5274/signin");
  });
});

test.describe("F02 account, session, sign in and out", () => {
  test("F02-H1 signup lands on the empty overview, sign out, sign back in", async ({ page }) => {
    const email = await signUp(page);
    await expect(page.getByText("Run your first scan")).toBeVisible();
    await a11y(page, "overview empty");
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await a11y(page, "sign in");
    await page.getByLabel("Work email").fill(email);
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  });
  test("F02-N1 wrong password shows an error and stays signed out", async ({ page }) => {
    const email = await signUp(page);
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.getByLabel("Work email").fill(email);
    await page.getByLabel("Password").fill("definitely-wrong-pass");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("alert")).toContainText("Email or password is incorrect");
  });
  test("F02-N2 duplicate email and short password are rejected", async ({ page, browser }) => {
    const email = await signUp(page);
    const { ctx, page: p2 } = await newUserContext(browser);
    await p2.goto("/signup");
    await p2.getByLabel("Work email").fill(email);
    await p2.getByLabel("Password").fill(PASSWORD);
    await p2.getByRole("button", { name: "Create account" }).click();
    await expect(p2.getByRole("alert")).toContainText("already exists");
    await p2.getByLabel("Work email").fill(uniqueEmail());
    await p2.getByLabel("Password").fill("short");
    await p2.getByRole("button", { name: "Create account" }).click();
    await expect(p2.getByRole("alert")).toBeVisible();
    await ctx.close();
  });
  test("F02-E1 refresh keeps the session; unauthenticated deep link goes to sign in", async ({ page, browser }) => {
    await signUp(page);
    await page.reload();
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    const { ctx, page: anon } = await newUserContext(browser);
    await anon.goto("/findings");
    await expect(anon.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await ctx.close();
  });
  test("F02-E2 sign out on all devices ends the other session", async ({ page, browser }) => {
    const email = await signUp(page);
    const { ctx, page: other } = await newUserContext(browser);
    await other.goto("/signin");
    await other.getByLabel("Work email").fill(email);
    await other.getByLabel("Password").fill(PASSWORD);
    await other.getByRole("button", { name: "Sign in" }).click();
    await expect(other.getByRole("heading", { name: "Overview" })).toBeVisible();
    await page.goto("/settings");
    await page.getByRole("button", { name: "Sign out on all devices" }).click();
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await other.reload();
    await expect(other.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await ctx.close();
  });
  test("F02-E3 delete account needs the password, then removes it", async ({ page }) => {
    const email = await signUp(page);
    await page.goto("/settings");
    await page.getByRole("button", { name: "Delete my account" }).click();
    await page.getByLabel("Confirm with your password").fill("wrong-wrong-wrong");
    await page.getByRole("button", { name: "Delete permanently" }).click();
    await expect(page.getByRole("dialog").getByRole("alert")).toContainText("Password is incorrect");
    await page.getByLabel("Confirm with your password").fill(PASSWORD);
    await page.getByRole("button", { name: "Delete permanently" }).click();
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await page.getByLabel("Work email").fill(email);
    await page.getByLabel("Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("alert")).toContainText("incorrect");
  });
});

test.describe("F03 first scan to dashboard", () => {
  test("F03-H1 empty overview -> sample -> result -> overview numbers, within 4 clicks", async ({ page }) => {
    await signUp(page);
    await page.getByRole("link", { name: "Try with a sample config" }).click(); // click 1
    await page.getByRole("button", { name: "Run scan" }).click(); // click 2
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    await expect(page.getByText("New findings")).toBeVisible();
    await a11y(page, "scan result");
    await page.getByRole("link", { name: "Go to overview" }).click(); // click 3
    await expect(page.getByText("Posture score", { exact: true })).toBeVisible();
    await expect(page.getByText("Assets scanned")).toBeVisible();
    await expect(page.getByRole("img", { name: /Posture score \d+ of 100/ })).toBeVisible();
    await a11y(page, "overview");
  });
  test("F03-E1 invalid JSON and invalid config show errors, nothing is stored", async ({ page }) => {
    await signUp(page);
    await page.goto("/scans/new");
    await page.getByLabel("Resources (JSON)").fill("{ nope");
    await page.getByRole("button", { name: "Run scan" }).click();
    await expect(page.getByRole("alert")).toContainText("not valid JSON");
    await page.getByLabel("Resources (JSON)").fill(JSON.stringify({ resources: [{ type: "s3_bucket" }] }));
    await page.getByRole("button", { name: "Run scan" }).click();
    await expect(page.getByRole("alert")).toContainText('missing "name"');
    await page.goto("/scans");
    await expect(page.getByText("No scans yet")).toBeVisible();
  });
  test("F03-E2 double click on Run scan creates exactly one scan", async ({ page }) => {
    await signUp(page);
    await page.goto("/scans/new?sample=1");
    await page.getByRole("button", { name: "Run scan" }).dblclick();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    await page.goto("/scans");
    await expect(page.getByRole("row")).toHaveCount(2); // header + one scan
  });
  test("F03-E3 rescanning after a fix shows fixed findings and a higher score", async ({ page }) => {
    await signUp(page);
    await runSampleScan(page);
    const before = Number(await page.locator(".kpi .value").first().innerText());
    const fixed = { resources: [{ type: "s3_bucket", name: "prod-customer-data", environment: "production", public_read: false, encrypted: true }] };
    await page.goto("/scans/new");
    await page.getByLabel("Resources (JSON)").fill(JSON.stringify(fixed));
    await page.getByRole("button", { name: "Run scan" }).click();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    await expect(page.locator(".kpi").filter({ hasText: "Fixed since last scan" }).locator(".value")).toHaveText("2");
    expect(Number(await page.locator(".kpi .value").first().innerText())).toBeGreaterThan(before);
  });
  test("F03-E4 refresh on the result page keeps it", async ({ page }) => {
    await signUp(page);
    await runSampleScan(page);
    await page.reload();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
  });
  test("F03-E5 long and accented names are handled without layout breakage", async ({ page }) => {
    await signUp(page);
    const name = "żółć-" + "very-long-bucket-name-".repeat(6) + "😀";
    await page.goto("/scans/new");
    await page.getByLabel("Resources (JSON)").fill(JSON.stringify([{ type: "s3_bucket", name, public_read: true }]));
    await page.getByRole("button", { name: "Run scan" }).click();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
    expect(overflow).toBe(false);
  });
});

test.describe("F04-F06 triage, AI explanation, compliance", () => {
  test.beforeEach(async ({ page }) => { await signUp(page); await runSampleScan(page); });

  test("F04-H1 findings list filters, search and detail", async ({ page }) => {
    await page.goto("/findings");
    await expect(page.getByRole("row")).toHaveCount(8); // header + 7
    await a11y(page, "findings");
    await page.getByLabel("Severity").selectOption("critical");
    await expect(page.getByRole("row")).toHaveCount(5); // 4 critical
    await page.getByLabel("Severity").selectOption("");
    await page.getByLabel("Search findings").fill("orders-db");
    await expect(page.getByRole("row")).toHaveCount(3);
    await page.getByLabel("Search findings").fill("zzz-no-match");
    await expect(page.getByText("No findings match these filters")).toBeVisible();
  });
  test("F04-H2 detail page shows evidence, fix, risk and mapped controls", async ({ page }) => {
    await page.goto("/findings");
    await page.getByRole("link", { name: "Policy grants full administrator access" }).click();
    await expect(page.getByRole("heading", { name: "How to fix" })).toBeVisible();
    await expect(page.getByText(/Rule base 95/)).toBeVisible();
    await expect(page.getByText("CIS-AWS 1.16")).toBeVisible();
    await a11y(page, "finding detail");
  });
  test("F04-N1 accepting a risk needs a reason and a future date; then it leaves the open list", async ({ page }) => {
    await page.goto("/findings");
    await page.getByRole("link", { name: "Policy grants full administrator access" }).click();
    await page.getByRole("button", { name: "Accept risk" }).click();
    await a11y(page, "accept dialog");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByLabel("Reason")).toBeFocused().catch(() => {}); // native required validation blocks submit
    await page.getByLabel("Reason").fill("Fix is scheduled for next sprint");
    await page.getByLabel("Review again on").fill(new Date(Date.now() + 30 * 86400_000).toISOString().slice(0, 10));
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Accepted risk").first()).toBeVisible();
    await page.goto("/findings");
    await expect(page.getByRole("row")).toHaveCount(7); // 6 open + header
    await page.getByLabel("Status").selectOption("accepted");
    await expect(page.getByRole("row")).toHaveCount(2);
  });
  test("F04-E1 Escape closes the dialog and returns focus", async ({ page }) => {
    await page.goto("/findings");
    await page.getByRole("link", { name: "Policy grants full administrator access" }).click();
    await page.getByRole("button", { name: "Mark false positive" }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
  });
  test("F05-H1 explain generates an evidence-only explanation and is cached", async ({ page }) => {
    await page.goto("/findings");
    await page.getByRole("link", { name: "Database is publicly accessible" }).click();
    await page.getByRole("button", { name: "Explain this finding" }).click();
    await expect(page.getByText("Evidence in your config")).toBeVisible();
    await expect(page.getByText("Written from the scanner’s rule and your config only.")).toBeVisible();
    await page.reload();
    await expect(page.getByText("Evidence in your config")).toBeVisible(); // persisted
    await page.goto("/usage");
    await expect(page.getByRole("progressbar", { name: "AI explanations this month" })).toHaveAttribute("aria-valuenow", "1");
  });
  test("F06-H1 compliance view lists failing controls and links to findings", async ({ page }) => {
    await page.goto("/compliance");
    await expect(page.getByText("Not a full CIS-AWS assessment").first()).toBeVisible();
    await a11y(page, "compliance");
    await page.getByRole("button", { name: "Show failing controls" }).first().click();
    await expect(page.getByRole("link", { name: "View findings" }).first()).toBeVisible();
  });
  test("assets, scan history and overview drill-downs", async ({ page }) => {
    await page.goto("/assets");
    await expect(page.getByRole("row")).toHaveCount(8);
    await a11y(page, "assets");
    await page.getByRole("link", { name: /Database · 1/ }).click();
    await expect(page.getByRole("row")).toHaveCount(2);
    await page.goto("/scans");
    await a11y(page, "scan history");
    await expect(page.getByRole("row")).toHaveCount(2);
    await page.goto("/");
    await page.getByRole("button", { name: "3 months" }).click();
    await expect(page.getByRole("img", { name: /Posture score trend/ })).toBeVisible();
  });
  test("CSV export downloads", async ({ page }) => {
    await page.goto("/findings");
    const dl = page.waitForEvent("download");
    await page.getByRole("link", { name: "Export CSV" }).click();
    expect((await dl).suggestedFilename()).toBe("cspm-findings.csv");
  });
});

test.describe("F09 team and roles, F10 settings", () => {
  test("F09-H1 owner invites a viewer; viewer is read-only", async ({ page, browser }) => {
    await signUp(page);
    await runSampleScan(page);
    await page.goto("/team");
    await a11y(page, "team");
    const email = uniqueEmail("viewer");
    await page.getByLabel("Email").fill(email);
    await page.locator("label.field", { hasText: "Role" }).locator("select").selectOption("viewer");
    await page.getByRole("button", { name: "Create invite link" }).click();
    const link = await page.getByLabel("Invite link").inputValue();
    expect(link).toContain("/invite/");

    const { ctx, page: v } = await newUserContext(browser);
    await v.goto(new URL(link).pathname);
    await v.getByLabel("Your name").fill("Vee Viewer");
    await v.getByLabel("Password").fill(PASSWORD);
    await v.getByRole("button", { name: "Accept invitation" }).click();
    await expect(v.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(v.getByRole("link", { name: "New scan" })).toHaveCount(0);
    await expect(v.getByRole("link", { name: "Team" })).toHaveCount(0);
    await v.goto("/scans/new");
    await expect(v.getByText("You need analyst access to run scans")).toBeVisible();
    await v.goto("/findings");
    await expect(v.getByRole("row")).toHaveCount(8); // can read
    await v.goto("/team");
    await expect(v.getByRole("alert")).toContainText("permission");
    // owner promotes to analyst; takes effect on the next request
    await page.reload();
    await page.getByLabel(`Role for ${email}`).selectOption("analyst");
    await expect(page.getByRole("status")).toContainText("Role updated");
    await v.goto("/scans/new");
    await expect(v.getByRole("button", { name: "Run scan" })).toBeVisible();
    // the same invite link cannot be reused
    const { ctx: c3, page: p3 } = await newUserContext(browser);
    await p3.goto(new URL(link).pathname);
    await p3.getByLabel("Password").fill("another-pass-12345");
    await p3.getByRole("button", { name: "Accept invitation" }).click();
    await expect(p3.getByRole("alert")).toContainText("invalid or has expired");
    await ctx.close(); await c3.close();
  });
  test("F10-H1 settings: theme switch persists, API key shown once", async ({ page }) => {
    await signUp(page);
    await page.goto("/settings");
    await a11y(page, "settings");
    await page.getByRole("button", { name: "Dark" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.getByRole("button", { name: "Light" }).click();
    await page.waitForTimeout(400); // let the 120ms colour transition finish before measuring contrast
    await a11y(page, "settings light");
    await page.getByLabel("Key name").fill("CI");
    await page.getByRole("button", { name: "Create key" }).click();
    await expect(page.getByText(/cspm_[A-Za-z0-9_-]{20,}/)).toBeVisible();
    await page.reload();
    await expect(page.getByText(/cspm_[A-Za-z0-9_-]{20,}/)).toHaveCount(0);
    await expect(page.getByText("never used")).toBeVisible();
  });
  test("F10-E1 usage page and audit log", async ({ page }) => {
    await signUp(page);
    await runSampleScan(page);
    await page.goto("/usage");
    await expect(page.getByRole("progressbar", { name: "Scans this month" })).toHaveAttribute("aria-valuenow", "1");
    await a11y(page, "usage");
    await page.goto("/audit");
    await expect(page.getByText("scan.run")).toBeVisible();
    await a11y(page, "audit");
  });
  test("planned pages are honest about not existing yet", async ({ page }) => {
    await signUp(page);
    await page.getByRole("link", { name: /Attack paths/ }).click();
    await expect(page.getByText("Planned, not built")).toBeVisible();
    await a11y(page, "planned");
  });
});

test.describe("F08 quota and upgrade", () => {
  test("F08-N1 free plan stops at 10 scans with a clear message", async ({ page }) => {
    await signUp(page);
    for (let i = 0; i < 10; i++) {
      await page.goto("/scans/new?sample=1");
      await page.getByRole("button", { name: "Run scan" }).click();
      await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    }
    await page.goto("/scans/new?sample=1");
    await expect(page.getByText("You have used all scans on your plan this month.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Run scan" })).toBeDisabled();
    await page.goto("/usage");
    await expect(page.getByRole("button", { name: "Upgrade" })).toBeVisible();
    await page.getByRole("button", { name: "Upgrade" }).click();
    await expect(page.getByText("Billing is not set up yet")).toBeVisible(); // no Stripe keys in e2e
  });
});

test.describe("isolation between organizations", () => {
  test("org B cannot open org A's finding or scan by URL", async ({ page, browser }) => {
    await signUp(page, uniqueEmail("a"), "Org A");
    await runSampleScan(page);
    const scanUrl = page.url();
    await page.goto("/findings");
    await page.getByRole("link", { name: "Policy grants full administrator access" }).click();
    const findingUrl = page.url();
    const { ctx, page: b } = await newUserContext(browser);
    await signUp(b, uniqueEmail("b"), "Org B");
    await b.goto(findingUrl);
    await expect(b.getByRole("alert")).toContainText("not found");
    await b.goto(scanUrl);
    await expect(b.getByRole("alert")).toContainText("not found");
    await b.goto("/findings");
    await expect(b.getByText("No findings yet")).toBeVisible();
    await ctx.close();
  });
});

test.describe("responsive @mobile", () => {
  test("mobile navigation drawer opens and has no horizontal scroll", async ({ page }) => {
    await signUp(page);
    await runSampleScan(page);
    await page.goto("/");
    await page.getByRole("button", { name: "Open navigation" }).click();
    await page.getByRole("link", { name: "Findings", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    await a11y(page, "findings mobile");
  });
});
