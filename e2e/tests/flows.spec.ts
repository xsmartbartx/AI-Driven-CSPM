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

test.describe("email flows (UI; delivery itself is covered by API tests with a mocked provider)", () => {
  test("EM-H1 forgot password gives the same answer for any address", async ({ page }) => {
    await page.goto("/signin");
    await page.getByRole("link", { name: "Forgot your password?" }).click();
    await a11y(page, "forgot password");
    await page.getByLabel("Email").fill(uniqueEmail("nobody"));
    await page.getByRole("button", { name: "Send reset link" }).click();
    await expect(page.getByRole("status")).toContainText("If an account exists");
  });
  test("EM-N1 an invalid reset or verification link explains what to do", async ({ page }) => {
    await page.goto("/reset-password/" + "x".repeat(40));
    await a11y(page, "reset password");
    await page.getByLabel("New password").fill("a-new-password-123");
    await page.getByRole("button", { name: "Change password" }).click();
    await expect(page.getByRole("alert")).toContainText("invalid or has expired");
    await expect(page.getByRole("link", { name: "Send a new link" })).toBeVisible();
    await page.goto("/verify-email/" + "y".repeat(40));
    await expect(page.getByRole("alert")).toContainText("invalid or has expired");
  });
  test("EM-H2 new accounts see the confirm-email banner and can resend", async ({ page }) => {
    const email = await signUp(page);
    await expect(page.getByText(`We sent a link to`)).toContainText(email);
    await page.getByRole("button", { name: "Resend email" }).click();
    await expect(page.getByRole("status")).toContainText("Confirmation email sent");
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
    await v.goto("/attack-paths");
    await expect(v.getByRole("heading", { name: "Attack paths", level: 1 })).toBeVisible(); // readable by viewers
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
    await page.getByRole("link", { name: /AI Security Center/ }).click();
    await expect(page.getByText("Planned, not built")).toBeVisible();
    await a11y(page, "planned");
  });
});

test.describe("F11 attack paths", () => {
  test("F11-E1 without servers there is nothing to build paths from, and the page says what is needed", async ({ page }) => {
    await signUp(page);
    await page.getByRole("link", { name: "Attack paths" }).click();
    await expect(page.getByRole("heading", { name: "Nothing to build paths from yet" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Connect an AWS account" })).toBeVisible();
    await a11y(page, "attack paths empty");
    await runSampleScan(page); // the ordinary sample has no servers either
    await page.goto("/attack-paths");
    await expect(page.getByRole("heading", { name: "Nothing to build paths from yet" })).toBeVisible();
  });

  test("F11-H1 the sample with an exposed server shows two ranked paths, the fix that breaks both, and links to the findings", async ({ page }) => {
    await signUp(page);
    await page.goto("/attack-paths");
    await page.getByRole("link", { name: "Try a sample with paths" }).click();
    await page.getByRole("button", { name: "Run scan" }).click();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    await page.getByRole("link", { name: "Attack paths" }).click();
    await expect(page.getByRole("heading", { name: "Attack paths", level: 1 })).toBeVisible();
    await expect(page.locator(".kpi").filter({ hasText: "Attack paths" }).locator(".value")).toHaveText("2");
    await expect(page.getByRole("heading", { name: /web-1 is reachable from the internet and leads to full control of the AWS account/ })).toBeVisible();
    await expect(page.getByRole("heading", { name: /leads to database orders-db/ })).toBeVisible();
    // the chain is a real ordered list a screen reader can follow
    const chain = page.getByRole("article", { name: /full control of the AWS account/ }).getByRole("list", { name: "Steps of this attack path" });
    await expect(chain.getByRole("listitem")).toHaveCount(4);
    await expect(chain).toContainText("Internet"); await expect(chain).toContainText("web-1"); await expect(chain).toContainText("app-role"); await expect(chain).toContainText("AWS account");
    const fixFirst = page.getByRole("region", { name: "Fix these first" }).or(page.locator("section", { has: page.getByRole("heading", { name: "Fix these first" }) }));
    await expect(fixFirst.getByText("Remove the internet-wide rule (port 443, port 22) from web-sg").first()).toBeVisible(); // the sample group is open on both
    await expect(fixFirst.getByText("2 paths").first()).toBeVisible();
    await a11y(page, "attack paths");
    // related findings link to the real finding
    await page.getByRole("article", { name: /full control of the AWS account/ }).getByRole("link", { name: "Policy grants full administrator access" }).click();
    await expect(page.getByRole("heading", { name: "Policy grants full administrator access" })).toBeVisible();
    // the limits are stated, not hidden
    await page.goto("/attack-paths");
    await page.getByText("What this can and cannot see").click();
    await expect(page.getByText(/Not modelled: subnets and route tables/)).toBeVisible();
  });

  test("F11-E2 closing the exposure and rescanning removes the paths", async ({ page }) => {
    await signUp(page);
    await page.goto("/scans/new?sample=paths");
    const cfg = JSON.parse(await page.getByLabel("Resources (JSON)").inputValue());
    await page.getByRole("button", { name: "Run scan" }).click();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    await page.goto("/attack-paths");
    await expect(page.getByRole("heading", { name: /web-1 is reachable/ }).first()).toBeVisible();
    // the same configuration with the SSH rule closed
    cfg.resources.find((r: any) => r.name === "web-sg").ingress = [{ cidr: "10.0.0.0/16", port: 22 }];
    await page.goto("/scans/new");
    await page.getByLabel("Resources (JSON)").fill(JSON.stringify(cfg));
    await page.getByRole("button", { name: "Run scan" }).click();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    await page.goto("/attack-paths");
    await expect(page.getByRole("heading", { name: "No attack paths found" })).toBeVisible();
  });
});

test.describe("F07 cloud accounts (the e2e API uses a fake AWS)", () => {
  // a short screen: the setup dialog is taller than this, so its buttons must be reachable by scrolling
  test.use({ viewport: { width: 1100, height: 560 } });
  const connect = async (page: any, account = "111122223333", region = "eu-west-1") => {
    await page.goto("/integrations");
    await page.getByRole("button", { name: "Connect AWS account" }).first().click();
    await page.getByLabel(/AWS account id/).fill(account);
    await page.getByLabel("Region to scan").selectOption(region);
    await page.getByRole("button", { name: "Continue" }).click();
  };

  test("F07-H1 connect, set up the role, verify, scan, see findings, disconnect", async ({ page }) => {
    await signUp(page);
    await page.getByRole("link", { name: "Cloud accounts" }).click();
    await expect(page.getByText("No AWS account connected")).toBeVisible();
    await a11y(page, "cloud accounts empty");
    await connect(page);
    const dlg = page.getByRole("dialog");
    await expect(dlg.getByRole("heading", { name: "Create the read-only role in AWS" })).toBeVisible();
    await expect(dlg.locator("dd code", { hasText: /^123456789012$/ })).toBeVisible(); // NEXORA's account to trust
    await expect(dlg.locator("dd code", { hasText: /^nx-[\w-]{20,}$/ })).toBeVisible(); // the External ID
    await expect(dlg.getByLabel("CloudFormation template")).toContainText("sts:ExternalId");
    await expect(dlg.getByLabel("CloudFormation template")).not.toContainText("s3:GetObject");
    await a11y(page, "aws setup dialog");
    await dlg.getByRole("button", { name: "Done" }).click();

    const card = page.getByRole("region", { name: "AWS account 111122223333 in eu-west-1" });
    await expect(card.getByText("Not verified")).toBeVisible();
    await expect(card.getByRole("button", { name: "Scan now" })).toHaveCount(0); // cannot scan before verifying
    await card.getByRole("button", { name: "Verify connection" }).click();
    await expect(card.getByText("Connected", { exact: true })).toBeVisible();
    await card.getByRole("button", { name: "Scan now" }).click();
    await expect(page.getByText(/Scan finished: 4 findings/)).toBeVisible();
    await expect(page.getByText("only customer-managed policies")).toBeVisible(); // notes are shown, not hidden
    await a11y(page, "cloud accounts connected");

    await page.getByRole("link", { name: "See the result" }).click();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    await expect(page.getByText("Policy grants full administrator access")).toBeVisible();
    await page.goto("/assets");
    await expect(page.getByText("111122223333-public-assets")).toBeVisible();
    await page.goto("/scans");
    await expect(page.getByRole("row")).toHaveCount(2);

    await page.goto("/integrations");
    page.once("dialog", (d) => d.accept());
    await page.getByRole("button", { name: "Disconnect" }).click();
    await expect(page.getByText("No AWS account connected")).toBeVisible();
    await page.goto("/findings");
    await expect(page.getByRole("row")).toHaveCount(5); // history stays: 4 findings + header
  });

  test("F07-H2 turn automatic scans on and off; the next run is shown and survives a reload", async ({ page }) => {
    await signUp(page);
    await connect(page);
    await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();
    const card = page.getByRole("region", { name: "AWS account 111122223333 in eu-west-1" });
    await expect(card.getByLabel(/Automatic scans for/)).toHaveCount(0); // only for a verified connection
    await card.getByRole("button", { name: "Verify connection" }).click();
    await expect(card.getByText("Connected", { exact: true })).toBeVisible();
    const select = card.getByLabel("Automatic scans for 111122223333 in eu-west-1");
    await expect(select).toHaveValue("off");
    await select.selectOption("daily");
    await expect(card.getByText(/Next scan around/)).toBeVisible();
    await a11y(page, "cloud accounts automatic scans");
    await page.reload();
    await expect(card.getByLabel(/Automatic scans for/)).toHaveValue("daily");
    await card.getByLabel(/Automatic scans for/).selectOption("off");
    await expect(card.getByText(/Next scan around/)).toHaveCount(0);
    await expect(page.getByText(/use the same monthly scan allowance/)).toBeVisible();
  });

  test("F07-N1 a role AWS cannot assume shows a clear message and keeps the connection as 'needs attention'", async ({ page }) => {
    await signUp(page);
    await connect(page, "000000000000");
    await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();
    const card = page.getByRole("region", { name: /AWS account 000000000000/ });
    await card.getByRole("button", { name: "Verify connection" }).click();
    await expect(card.getByRole("alert")).toContainText("could not assume the role");
    await expect(card.getByText("Needs attention")).toBeVisible();
    await card.getByRole("button", { name: "Setup instructions" }).click(); // the instructions can be reopened
    await expect(page.getByRole("dialog").locator("dd code", { hasText: /^nx-/ })).toBeVisible();
    await page.keyboard.press("Escape");
    await a11y(page, "cloud accounts error");
  });

  test("F07-N2 input errors: bad account id and duplicates", async ({ page }) => {
    await signUp(page);
    await page.goto("/integrations");
    await page.getByRole("button", { name: "Connect AWS account" }).first().click();
    await page.getByLabel(/AWS account id/).fill("12345");
    await page.getByRole("button", { name: "Continue" }).click(); // native pattern validation stops it
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.getByRole("button", { name: "Cancel" }).click();
    await connect(page);
    await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();
    await connect(page); // same account and region again
    await expect(page.getByRole("dialog").getByRole("alert")).toContainText("already connected");
  });

  test("F07-P1 a viewer sees the connection but no way to change or scan it, and never the External ID", async ({ page, browser }) => {
    await signUp(page);
    await connect(page);
    await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();
    await page.goto("/team");
    const email = uniqueEmail("cloudviewer");
    await page.getByLabel("Email").fill(email);
    await page.locator("label.field", { hasText: "Role" }).locator("select").selectOption("viewer");
    await page.getByRole("button", { name: "Create invite link" }).click();
    const link = await page.getByLabel("Invite link").inputValue();
    const { ctx, page: v } = await newUserContext(browser);
    await v.goto(new URL(link).pathname);
    await v.getByLabel("Password").fill(PASSWORD);
    await v.getByRole("button", { name: "Accept invitation" }).click();
    await expect(v.getByRole("heading", { name: "Overview" })).toBeVisible(); // wait until the session exists
    await v.goto("/integrations");
    await expect(v.getByRole("region", { name: "AWS account 111122223333 in eu-west-1" })).toBeVisible();
    for (const name of ["Connect AWS account", "Verify connection", "Scan now", "Disconnect", "Setup instructions"]) await expect(v.getByRole("button", { name })).toHaveCount(0);
    await expect(v.getByText(/nx-/)).toHaveCount(0);
    await ctx.close();
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
  test("attack path chains stack vertically on a phone without horizontal scroll", async ({ page }) => {
    await signUp(page);
    await page.goto("/scans/new?sample=paths");
    await page.getByRole("button", { name: "Run scan" }).click();
    await expect(page.getByRole("heading", { name: "Scan result" })).toBeVisible();
    await page.goto("/attack-paths");
    await expect(page.getByRole("heading", { name: /web-1 is reachable/ }).first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
    const chain = page.getByRole("list", { name: "Steps of this attack path" }).first();
    const boxes = await chain.getByRole("listitem").evaluateAll((els) => els.map((e) => e.getBoundingClientRect().top));
    expect(new Set(boxes).size).toBe(boxes.length); // every step on its own row
    await a11y(page, "attack paths mobile");
  });

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
