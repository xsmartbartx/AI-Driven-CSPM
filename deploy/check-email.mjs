#!/usr/bin/env node
// Checks your Resend setup from your own machine. You run it; it needs your key, which I never see.
//   RESEND_API_KEY=re_... MAIL_FROM="NEXORA CSPM <no-reply@mail.cspm.onenexora.com>" node deploy/check-email.mjs [you@example.com]
// With an address it also sends one test email there. Exit code 1 if anything is wrong. Never prints the key.
const base = (process.env.RESEND_API_BASE ?? "https://api.resend.com").replace(/\/$/, "");
const key = process.env.RESEND_API_KEY ?? "";
const from = process.env.MAIL_FROM ?? "";
const to = process.argv[2];
let bad = 0;
let sendOnly = false;
const ok = (m) => console.log(`  ok   ${m}`);
const no = (m) => { bad++; console.log(`  FAIL ${m}`); };
const note = (m) => console.log(`  note ${m}`);

const api = async (method, path, body) => {
  try {
    // bounded, so a stalled connection ends in a clear failure instead of hanging the check
    const res = await fetch(base + path, { method, headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: body && JSON.stringify(body), signal: AbortSignal.timeout(15_000) });
    let json = null; try { json = await res.json(); } catch { /* no body */ }
    return { status: res.status, json };
  } catch (e) {
    return { status: 0, json: { message: e?.name === "TimeoutError" ? "the request timed out after 15 seconds" : `could not reach ${base} (${e?.cause?.code ?? e?.name ?? "network error"})` } };
  }
};

console.log("Resend email check");
if (!key) no("RESEND_API_KEY is not set");
else if (!key.startsWith("re_")) no("RESEND_API_KEY does not look like a Resend key (they start with re_)");
else ok("API key is set");

const addr = (from.match(/<([^>]+)>/)?.[1] ?? from).trim();
const domain = addr.includes("@") ? addr.split("@")[1].toLowerCase() : "";
if (!from) no('MAIL_FROM is not set, e.g. MAIL_FROM="NEXORA CSPM <no-reply@mail.cspm.onenexora.com>"');
else if (!domain) no(`MAIL_FROM has no address: ${from}`);
else ok(`sending as ${addr} (domain ${domain})`);

if (key && domain) {
  const d = await api("GET", "/domains");
  // Resend answers 401 "restricted_api_key" for a send-only key. Any other 401/403 (invalid or inactive key) is a real failure.
  if (d.status === 401 && d.json?.name === "restricted_api_key") {
    sendOnly = true;
    note("this key is send-only (recommended), so the domain list cannot be read; the test email below is the real check");
  } else if (d.status !== 200) {
    no(`could not list domains (HTTP ${d.status}${d.json?.message ? `: ${d.json.message}` : ""})`);
  } else {
    const found = (d.json?.data ?? []).find((x) => x.name?.toLowerCase() === domain);
    if (!found) no(`domain ${domain} is not in your Resend account. Add it under Domains, then add the DNS records Resend shows.`);
    else if (found.status === "verified") ok(`domain ${domain} is verified`);
    else if (found.capabilities?.sending === "enabled") ok(`domain ${domain} can send (status "${found.status}": other records, such as receiving, are still pending)`);
    else if (String(found.status).startsWith("partially")) note(`domain ${domain} is "${found.status}". Sending may still work; the test email decides.`);
    else {
      no(`domain ${domain} is "${found.status}". Add or fix the DNS records, then press Verify in Resend.`);
      const det = await api("GET", `/domains/${found.id}`);
      for (const r of det.json?.records ?? []) console.log(`         ${r.status === "verified" ? "ok     " : "PENDING"} ${r.record ?? ""} ${r.type ?? ""} ${r.name ?? ""}`);
    }
  }
  if (to) {
    const s = await api("POST", "/emails", { from, to: [to], subject: "NEXORA CSPM email check", text: "If you can read this, sending works. You can delete it." });
    if (s.status === 200 || s.status === 201) ok(`test email accepted by Resend (id ${s.json?.id ?? "?"}); check the inbox and the spam folder of ${to}`);
    else no(`test email refused (HTTP ${s.status}${s.json?.message ? `: ${s.json.message}` : ""})`);
  } else if (sendOnly) {
    no("a send-only key cannot be checked without sending: run again with a recipient address as the first argument");
  } else note("no recipient given, so no test email was sent. Add an address as the first argument to send one.");
}
console.log(bad ? `\n${bad} problem(s). Fix them and run again.` : "\nAll good.");
process.exit(bad ? 1 : 0);
