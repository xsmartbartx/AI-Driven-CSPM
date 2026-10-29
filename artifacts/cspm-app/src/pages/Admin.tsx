import { useState, type FormEvent } from "react";
import { Link } from "wouter";
import { api, ApiError, useApi } from "../api";
import { getTheme, setTheme, useMe, type Role } from "../App";
import { Dialog, Empty, ErrorBox, fmtDate, fmtTime, Skeleton } from "../ui";

export function Usage() {
  const { can, toast } = useMe();
  const { data, error, loading, reload } = useApi<any>("/usage");
  const [busy, setBusy] = useState(false);
  if (error) return <ErrorBox error={error} retry={reload} />;
  if (loading || !data) return <div className="card"><Skeleton lines={5} /></div>;
  const meter = (label: string, m: { used: number; limit: number }) => (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}><span>{label}</span><strong>{m.used} / {m.limit.toLocaleString()}</strong></div>
      <div className="bar" style={{ marginTop: 6 }} role="progressbar" aria-label={label} aria-valuenow={m.used} aria-valuemin={0} aria-valuemax={m.limit}><i style={{ width: `${Math.min(100, (m.used / m.limit) * 100)}%`, background: m.used >= m.limit ? "var(--danger)" : undefined }} /></div>
    </div>
  );
  async function upgrade() {
    setBusy(true);
    try { const r = await api<{ url: string }>("POST", "/billing/checkout"); window.location.href = r.url; }
    catch (e) { toast((e as ApiError).message); } finally { setBusy(false); }
  }
  async function portal() {
    setBusy(true);
    try { const r = await api<{ url: string }>("POST", "/billing/portal"); window.location.href = r.url; }
    catch (e) { toast((e as ApiError).message); } finally { setBusy(false); }
  }
  return (
    <>
      <div className="page-h"><div><h1>Usage &amp; plan</h1><p>You are on the {data.planLabel} plan. Usage resets {fmtDate(data.resetsAt)}.</p></div>{data.plan !== "free" && can("owner") && <button className="btn" onClick={portal} disabled={busy}>Manage or cancel subscription</button>}</div>
      <section className="card" style={{ display: "grid", gap: 16 }} aria-label="Usage this month">{meter("Scans this month", data.scans)}{meter("AI explanations this month", data.ai)}</section>
      <div className="grid g4">
        {data.plans.map((p: any) => (
          <section key={p.id} className={`card plan ${p.id === data.plan ? "cur" : ""}`}>
            <h2 className="h2">{p.label}</h2>
            <div className="price">{p.id === "enterprise" ? "Custom" : p.priceCents === 0 ? "$0" : `$${p.priceCents / 100}`}<span className="muted" style={{ fontSize: 14, fontWeight: 400 }}>{p.id !== "enterprise" && "/month"}</span></div>
            <p className="muted" style={{ margin: "8px 0 16px" }}>{p.id === "enterprise" ? "Custom limits, SSO and support." : `${p.scans} scans · ${p.ai} AI explanations`}</p>
            {p.id === data.plan ? <span className="chip ok">Current plan</span>
              : p.id === "starter" && data.plan === "free" ? <button className="btn primary" onClick={upgrade} disabled={busy || !can("owner")} title={!can("owner") ? "Only an owner can change the plan" : undefined}>Upgrade</button>
              : p.id === "enterprise" || p.id === "team" ? <a className="btn" href="mailto:sales@onenexora.com?subject=NEXORA%20CSPM%20plan">Contact us</a> : null}
          </section>
        ))}
      </div>
    </>
  );
}

export function Team() {
  const { me, toast } = useMe();
  const { data, error, loading, reload } = useApi<any>("/team");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [link, setLink] = useState("");
  const [emailed, setEmailed] = useState("");
  const [err, setErr] = useState("");
  async function invite(e: FormEvent) {
    e.preventDefault(); setErr(""); setLink("");
    try { const r = await api<any>("POST", "/team/invite", { email, role }); setLink(r.link); setEmailed(r.emailed ? r.email : ""); setEmail(""); reload(); } catch (x) { setErr((x as ApiError).message); }
  }
  const act = async (fn: () => Promise<unknown>, ok: string) => { try { await fn(); toast(ok); reload(); } catch (x) { toast((x as ApiError).message); } };
  return (
    <>
      <div className="page-h"><div><h1>Team</h1><p>Who can see and change what.</p></div></div>
      <section className="card" aria-labelledby="inv">
        <h2 className="h2" id="inv">Invite someone</h2>
        <form className="row" onSubmit={invite} style={{ alignItems: "flex-end" }}>
          <label className="field" style={{ flex: 1, minWidth: 220 }}>Email<input className="input" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label className="field">Role<select className="select" style={{ width: 140 }} value={role} onChange={(e) => setRole(e.target.value)}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></label>
          <button className="btn primary">Create invite link</button>
        </form>
        {err && <div className="err" role="alert" style={{ marginTop: 8 }}>{err}</div>}
        {link && (
          <div className="banner" style={{ marginTop: 12 }} role="status">
            {emailed ? <>We emailed the invitation to {emailed}. </> : <>We could not email this invitation, so send the link yourself. </>}The link works once and expires in 7 days.
            <div className="row" style={{ marginTop: 8, flexWrap: "nowrap" }}><input className="input" readOnly value={link} aria-label="Invite link" onFocus={(e) => e.target.select()} />
              <button className="btn" onClick={() => navigator.clipboard?.writeText(link).then(() => toast("Copied"), () => toast("Select the link and copy it"))}>Copy</button></div>
          </div>
        )}
      </section>
      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="card"><Skeleton lines={4} h={20} /></div>}
      {data && (
        <>
          <div className="card scroll-x" style={{ padding: 0 }}>
            <table className="tbl"><thead><tr><th>Member</th><th>Role</th><th>Joined</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>{data.members.map((m: any) => (
                <tr key={m.id}>
                  <td><strong>{m.name ?? m.email}</strong>{m.name && <div className="muted">{m.email}</div>}{m.email === me.user.email && <span className="chip" style={{ marginLeft: 6 }}>You</span>}</td>
                  <td><select className="select" style={{ width: 130 }} aria-label={`Role for ${m.email}`} value={m.role} disabled={m.role === "owner" && me.role !== "owner"}
                    onChange={(e) => act(() => api("PATCH", `/team/${m.id}`, { role: e.target.value as Role }), "Role updated")}>
                    {["viewer", "analyst", "admin", "owner"].map((r) => <option key={r} value={r} disabled={r === "owner" && me.role !== "owner"}>{r[0]!.toUpperCase() + r.slice(1)}</option>)}</select></td>
                  <td className="muted">{fmtDate(m.createdAt)}</td>
                  <td><button className="btn sm danger" onClick={() => confirm(`Remove ${m.email}?`) && act(() => api("DELETE", `/team/${m.id}`), "Member removed")}>Remove</button></td>
                </tr>))}</tbody></table>
          </div>
          {data.invites.length > 0 && (
            <section className="card"><h2 className="h2">Pending invitations</h2>
              <div className="list">{data.invites.map((i: any) => (
                <div key={i.id} className="row" style={{ justifyContent: "space-between" }}><span>{i.email} · {i.role}</span><span className="row"><span className="muted">expires {fmtDate(i.expiresAt)}</span><button className="btn sm" onClick={() => act(() => api("DELETE", `/team/invites/${i.id}`), "Invite cancelled")}>Cancel</button></span></div>))}</div>
            </section>
          )}
        </>
      )}
    </>
  );
}

export function Audit() {
  const { data, error, loading, reload } = useApi<any>("/audit");
  return (
    <>
      <div className="page-h"><div><h1>Audit log</h1><p>Who did what, most recent first.</p></div></div>
      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="card"><Skeleton lines={6} h={20} /></div>}
      {data && data.items.length === 0 && <Empty title="Nothing logged yet" />}
      {data && data.items.length > 0 && (
        <div className="card scroll-x" style={{ padding: 0 }}>
          <table className="tbl"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>IP</th></tr></thead>
            <tbody>{data.items.map((e: any) => <tr key={e.id}><td className="muted">{fmtTime(e.createdAt)}</td><td>{e.actor ?? "API key"}</td><td><code>{e.action}</code></td><td style={{ overflowWrap: "anywhere" }}>{e.target ?? ""}</td><td className="muted">{e.ip}</td></tr>)}</tbody></table>
        </div>
      )}
    </>
  );
}

export function Settings() {
  const { me, can, toast, setMe } = useMe();
  const [theme, setT] = useState(getTheme());
  const [del, setDel] = useState(false);
  const [delPw, setDelPw] = useState("");
  const [delErr, setDelErr] = useState("");
  const keys = useApi<any>(can("admin") ? "/api-keys" : null);
  const [name, setName] = useState("");
  const [fresh, setFresh] = useState("");
  const sups = useApi<any>(can("admin") ? "/suppressions" : null);
  const notif = useApi<any>(can("admin") ? "/notifications" : null);
  const [hook, setHook] = useState("");
  const [testOut, setTestOut] = useState("");
  async function saveNotif(patch: Record<string, unknown>) {
    try { await api("PUT", "/notifications", patch); setHook(""); notif.reload(); toast("Saved"); } catch (x) { toast((x as ApiError).message); }
  }
  const [access, setAccess] = useState("scan");
  const [days, setDays] = useState("90");
  async function create(e: FormEvent) {
    e.preventDefault();
    try { setFresh((await api<any>("POST", "/api-keys", { name, access, expiresInDays: days === "never" ? null : Number(days) })).key); setName(""); keys.reload(); } catch (x) { toast((x as ApiError).message); }
  }
  return (
    <>
      <div className="page-h"><div><h1>Settings</h1></div></div>
      <section className="card" aria-labelledby="org"><h2 className="h2" id="org">Organization</h2>
        <dl className="kv"><dt>Name</dt><dd>{me.org.name}</dd><dt>Plan</dt><dd>{me.org.plan} · <Link href="/usage">manage</Link></dd><dt>Your role</dt><dd>{me.role}</dd></dl></section>
      <section className="card" aria-labelledby="th"><h2 className="h2" id="th">Appearance</h2>
        <div className="seg" role="group" aria-label="Theme">{["system", "light", "dark"].map((t) => <button key={t} aria-pressed={theme === t} onClick={() => { setTheme(t); setT(t); }}>{t[0]!.toUpperCase() + t.slice(1)}</button>)}</div></section>
      <section className="card" aria-labelledby="acct"><h2 className="h2" id="acct">Your account</h2>
        <div className="row">
          <button className="btn" onClick={async () => { await api("POST", "/auth/logout-all").catch(() => {}); setMe(null); }}>Sign out on all devices</button>
          <button className="btn danger" onClick={() => setDel(true)}>Delete my account</button>
        </div>
      </section>
      {del && (
        <Dialog title="Delete your account" onClose={() => setDel(false)}>
          <form style={{ display: "grid", gap: 16 }} onSubmit={async (e) => { e.preventDefault(); setDelErr(""); try { await api("DELETE", "/auth/me", me.user.hasPassword ? { password: delPw } : { confirmEmail: delPw }); setMe(null); } catch (x) { setDelErr((x as ApiError).message); } }}>
            <p>This permanently deletes your account. If you are the only member of your organization, its scans and findings are deleted too. This cannot be undone.</p>
            {me.user.hasPassword
              ? <label className="field">Confirm with your password<input className="input" type="password" autoComplete="current-password" required value={delPw} onChange={(e) => setDelPw(e.target.value)} /></label>
              : <label className="field">Type your email address ({me.user.email}) to confirm<input className="input" type="email" autoComplete="off" required value={delPw} onChange={(e) => setDelPw(e.target.value)} /></label>}
            {delErr && <div className="err" role="alert">{delErr}</div>}
            <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" className="btn" onClick={() => setDel(false)}>Cancel</button><button className="btn danger">Delete permanently</button></div>
          </form>
        </Dialog>
      )}
      {can("admin") && sups.data && (
        <section className="card" aria-labelledby="sp"><h2 className="h2" id="sp">Suppressed rules</h2>
          {sups.data.items.length === 0
            ? <p className="muted">None. Open a finding and choose "Suppress this rule" to stop a rule from counting for an asset, an environment, or everything.</p>
            : <div className="list">{sups.data.items.map((s: any) => (
                <div key={s.id} className="row" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
                  <span><strong>{s.ruleTitle}</strong> <span className="muted">· {s.assetName ? s.assetName : s.environment ? `all ${s.environment} assets` : "every asset"} · {s.suppressed} {s.suppressed === 1 ? "finding" : "findings"} · {s.expiresAt ? `until ${fmtDate(s.expiresAt)}` : "no expiry"}</span><br /><span className="muted">{s.reason}</span></span>
                  <button className="btn sm danger" onClick={async () => { if (confirm(`Remove this suppression? ${s.suppressed} suppressed finding(s) will reopen.`)) { await api("DELETE", `/suppressions/${s.id}`); sups.reload(); toast("Suppression removed"); } }}>Remove</button>
                </div>))}</div>}
        </section>
      )}
      {can("admin") && notif.data && (
        <section className="card" aria-labelledby="nt"><h2 className="h2" id="nt">Notifications</h2>
          <p className="muted" style={{ marginBottom: 12 }}>Get told when a scan finds new findings. Email goes to the organization's owners and admins; Slack needs an incoming webhook.</p>
          <div className="list">
            <label className="row"><input type="checkbox" checked={notif.data.emailEnabled} onChange={(e) => saveNotif({ emailEnabled: e.target.checked })} /> Email owners and admins</label>
            <label className="row">Alert on <select className="input" style={{ maxWidth: 200 }} value={notif.data.minSeverity} onChange={(e) => saveNotif({ minSeverity: e.target.value })}><option value="high">Critical and high</option><option value="critical">Critical only</option></select></label>
            <form className="row" onSubmit={(e) => { e.preventDefault(); saveNotif({ slackWebhook: hook }); }}>
              <input className="input" style={{ maxWidth: 360 }} type="password" autoComplete="off" aria-label="Slack webhook URL" placeholder={notif.data.slackConfigured ? "Slack webhook saved (paste a new URL to replace)" : "https://hooks.slack.com/services/…"} value={hook} onChange={(e) => setHook(e.target.value)} />
              <button className="btn" disabled={!hook}>Save Slack</button>
              {notif.data.slackConfigured && <button type="button" className="btn danger" onClick={() => saveNotif({ slackWebhook: null })}>Remove</button>}
            </form>
            <div className="row"><button className="btn" onClick={async () => { try { const o = await api<any>("POST", "/notifications/test"); setTestOut(`Email: ${o.email}. Slack: ${o.slack}.`); } catch (x) { setTestOut((x as ApiError).message); } }}>Send a test</button>
              <span className="muted" role="status">{testOut || (notif.data.lastError ? `Last problem: ${notif.data.lastError}` : notif.data.lastSentAt ? `Last alert sent ${fmtDate(notif.data.lastSentAt)}` : "")}</span></div>
          </div>
        </section>
      )}
      {can("admin") && (
        <section className="card" aria-labelledby="ak"><h2 className="h2" id="ak">API keys</h2>
          <p className="muted" style={{ marginBottom: 12 }}>A read-only key can read findings, assets and attack paths; a scan key can also run scans. Send them as <code>Authorization: Bearer cspm_…</code>.</p>
          <form className="row" onSubmit={create}><input className="input" style={{ maxWidth: 260 }} required maxLength={60} placeholder="Key name, e.g. CI pipeline" aria-label="Key name" value={name} onChange={(e) => setName(e.target.value)} /><select className="input" style={{ maxWidth: 170 }} aria-label="Access" value={access} onChange={(e) => setAccess(e.target.value)}><option value="scan">Read and run scans</option><option value="read">Read only</option></select><select className="input" style={{ maxWidth: 140 }} aria-label="Expires" value={days} onChange={(e) => setDays(e.target.value)}><option value="30">Expires in 30 days</option><option value="90">Expires in 90 days</option><option value="365">Expires in 1 year</option><option value="never">Never expires</option></select><button className="btn primary">Create key</button></form>
          {fresh && <div className="banner" role="status" style={{ marginTop: 12 }}>Copy this key now. You will not be able to see it again.<pre className="code" style={{ marginTop: 8 }}>{fresh}</pre></div>}
          {keys.data && keys.data.items.length > 0 && (
            <div className="list" style={{ marginTop: 12 }}>{keys.data.items.map((k: any) => (
              <div key={k.id} className="row" style={{ justifyContent: "space-between" }}><span><strong>{k.name}</strong> <code className="muted">{k.prefix}…</code> <span className="muted">{k.role === "viewer" ? "read only" : "read + scan"}</span></span>
                <span className="row"><span className="muted">{k.expiresAt ? (new Date(k.expiresAt) < new Date() ? "expired" : `expires ${fmtDate(k.expiresAt)}`) : "no expiry"} · {k.lastUsedAt ? `used ${fmtDate(k.lastUsedAt)}` : "never used"}</span>
                  <button className="btn sm danger" onClick={async () => { if (confirm(`Revoke ${k.name}?`)) { await api("DELETE", `/api-keys/${k.id}`); keys.reload(); } }}>Revoke</button></span></div>))}</div>
          )}
        </section>
      )}
    </>
  );
}
