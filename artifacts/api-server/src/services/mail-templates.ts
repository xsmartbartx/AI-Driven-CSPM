import { config } from "../config";
import type { Mail } from "./mail";

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

function layout(to: string, subject: string, lines: string[], cta: { label: string; url: string }, footer: string): Mail {
  const text = [...lines, "", `${cta.label}: ${cta.url}`, "", footer, "", "NEXORA CSPM"].join("\n");
  const html = `<!doctype html><html><body style="margin:0;background:#f5f6f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#15181d">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:12px;padding:32px">
<tr><td style="font-size:15px;font-weight:700;padding-bottom:16px">NEXORA CSPM</td></tr>
${lines.map((l) => `<tr><td style="font-size:15px;line-height:22px;padding-bottom:12px">${esc(l)}</td></tr>`).join("\n")}
<tr><td style="padding:12px 0 20px"><a href="${esc(cta.url)}" style="display:inline-block;background:#0b6a88;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 20px;border-radius:8px">${esc(cta.label)}</a></td></tr>
<tr><td style="font-size:13px;line-height:20px;color:#4f5864">If the button does not work, paste this link into your browser:<br><span style="word-break:break-all">${esc(cta.url)}</span></td></tr>
<tr><td style="font-size:13px;line-height:20px;color:#4f5864;padding-top:16px">${esc(footer)}</td></tr>
</table></td></tr></table></body></html>`;
  return { to, subject, text, html };
}

const base = () => config.appUrl.replace(/\/$/, "");

export const inviteEmail = (to: string, token: string, orgName: string, role: string, inviter: string | null): Mail =>
  layout(to, `You are invited to ${orgName} on NEXORA CSPM`,
    [`${inviter ?? "A teammate"} invited you to join ${orgName} as ${role}.`, "The link works once and expires in 7 days."],
    { label: "Accept invitation", url: `${base()}/invite/${token}` },
    "If you were not expecting this, you can ignore this email.");

export const resetEmail = (to: string, token: string): Mail =>
  layout(to, "Reset your NEXORA CSPM password",
    ["Someone asked to reset the password for this email address.", "The link works once and expires in 1 hour. Using it signs you out everywhere."],
    { label: "Choose a new password", url: `${base()}/reset-password/${token}` },
    "If you did not ask for this, ignore this email. Your password has not changed.");

export const verifyEmail = (to: string, token: string): Mail =>
  layout(to, "Confirm your email for NEXORA CSPM",
    ["Confirm this email address so we can reach you about your account.", "The link expires in 24 hours."],
    { label: "Confirm email", url: `${base()}/verify-email/${token}` },
    "If you did not create a NEXORA CSPM account, ignore this email.");

export const scheduledScanStoppedEmail = (to: string, orgName: string, account: string, reason: string): Mail =>
  layout(to, `Automatic AWS scans stopped for ${account}`,
    [`NEXORA stopped the automatic scans of AWS account ${account} for ${orgName}: ${reason}`, "Nothing else changed: your existing findings are still there, and you can still scan by hand."],
    { label: "Open cloud accounts", url: `${base()}/integrations` },
    "To start automatic scans again, fix the cause, press Verify connection, then choose Daily or Weekly.");

export const dailyBriefEmail = (to: string, orgName: string, brief: { headline: string; lines: string[]; newFindings: { items: { title: string; severity: string; assetName: string }[] } }): Mail =>
  layout(to, `${orgName}: ${brief.headline}`,
    [...brief.lines, ...brief.newFindings.items.map((f) => `New: ${f.severity.toUpperCase()} ${f.title} (${f.assetName})`)],
    { label: "Open the dashboard", url: `${base()}/` },
    "You get this once a day because the daily summary is on for your organization. Turn it off under Settings, Notifications.");

export const weeklyReportEmail = (to: string, orgName: string, brief: { lines: string[]; score: number | null; newFindings: { items: { title: string; severity: string; assetName: string }[] }; topRisks: { title: string; severity: string; assetName: string; riskScore: number }[] }): Mail =>
  layout(to, `${orgName}: your week in cloud security${brief.score !== null ? ` (score ${brief.score})` : ""}`,
    [...brief.lines.map((l) => l.replace(/ in the last week/, " this week")),
      ...brief.newFindings.items.map((f) => `New: ${f.severity.toUpperCase()} ${f.title} (${f.assetName})`),
      ...(brief.topRisks.length ? ["Highest risks right now:"] : []),
      ...brief.topRisks.map((f, i) => `${i + 1}. ${f.severity.toUpperCase()} ${f.title} on ${f.assetName} (risk ${f.riskScore})`)],
    { label: "Open the report", url: `${base()}/report` },
    "You get this every Monday because the weekly report is on for your organization. Turn it off under Settings, Notifications.");

export const securityAlertEmail = (to: string, orgName: string, alerts: { title: string; severity: string; asset: string }[], listed: number): Mail =>
  layout(to, `${alerts.length} new ${alerts.length === 1 ? "finding" : "findings"} for ${orgName}`,
    [`A scan found ${alerts.length} new ${alerts.length === 1 ? "finding" : "findings"} for ${orgName}.`,
      ...alerts.slice(0, listed).map((a) => `${a.severity.toUpperCase()}: ${a.title} (${a.asset})`),
      ...(alerts.length > listed ? [`…and ${alerts.length - listed} more.`] : [])],
    { label: "Open findings", url: `${base()}/findings` },
    "You get this because you are an owner or admin and alerts are on. Change it under Settings, Notifications.");
