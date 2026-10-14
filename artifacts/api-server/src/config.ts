import { randomBytes } from "node:crypto";

const prod = process.env["NODE_ENV"] === "production";
const secret = (k: string) => {
  const v = process.env[k];
  if (v) return v;
  if (prod) throw new Error(`${k} is required in production`);
  return randomBytes(32).toString("hex"); // dev: sessions reset on restart
};

export const PLANS = {
  free: { label: "Free", scans: 10, ai: 10, priceCents: 0 },
  starter: { label: "Starter", scans: 75, ai: 100, priceCents: 1900 },
  team: { label: "Team", scans: 500, ai: 1000, priceCents: 7900 },
  enterprise: { label: "Enterprise", scans: 100000, ai: 100000, priceCents: 0 },
} as const;
export type PlanId = keyof typeof PLANS;

export const config = {
  prod,
  port: Number(process.env["PORT"] ?? 8080),
  databaseUrl: process.env["DATABASE_URL"],
  dataDir: process.env["DATA_DIR"] ?? ".data/pglite",
  jwtSecret: secret("JWT_SECRET"),
  ssoSecret: process.env["SSO_SECRET"] ?? "", // empty disables SSO
  /** exact browser origins allowed to call the API with credentials */
  origins: (process.env["APP_ORIGINS"] ?? (prod ? "" : "http://localhost:5173,http://localhost:5174")).split(",").map((s) => s.trim()).filter(Boolean),
  appUrl: process.env["APP_URL"] ?? "http://localhost:5174",
  trustProxy: process.env["TRUST_PROXY"] === "1",
  stripeSecret: process.env["STRIPE_SECRET_KEY"] ?? "",
  stripeWebhookSecret: process.env["STRIPE_WEBHOOK_SECRET"] ?? "",
  stripeStarterPrice: process.env["STRIPE_PRICE_STARTER"] ?? "",
  /** Resend (https://resend.com). Without a key: dev logs emails to the console, production sends nothing. */
  resendKey: process.env["RESEND_API_KEY"] ?? "",
  mailFrom: process.env["MAIL_FROM"] ?? "NEXORA CSPM <no-reply@cspm.onenexora.com>",
  anthropicKey: process.env["ANTHROPIC_API_KEY"] ?? "",
  anthropicModel: process.env["ANTHROPIC_MODEL"] ?? "claude-haiku-5-5",
};
if (prod && config.resendKey && !process.env["MAIL_FROM"]) throw new Error("MAIL_FROM is required in production when RESEND_API_KEY is set");
if (prod && config.origins.length === 0) throw new Error("APP_ORIGINS is required in production");
