import { useState, type FormEvent } from "react";
import { Link, useLocation } from "wouter";
import { api, ApiError } from "../api";
import type { Me } from "../App";

function Brand() {
  return (
    <div className="row" style={{ gap: 10 }}>
      <svg width="32" height="32" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="var(--accent)" /><path d="M16 6l8 3v7c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V9z" fill="none" stroke="var(--on-accent)" strokeWidth="2" /></svg>
      <strong>NEXORA CSPM</strong>
    </div>
  );
}

export function AuthPage({ onAuth }: { onAuth: (m: Me) => void }) {
  const [loc, nav] = useLocation();
  const signup = loc === "/signup";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      const me = await api<Me>("POST", signup ? "/auth/signup" : "/auth/login", signup ? { email, password, orgName: orgName || undefined } : { email, password });
      onAuth(me);
      nav("/");
    } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  }
  return (
    <div className="auth">
      <form className="card" onSubmit={submit} noValidate>
        <Brand />
        <h1>{signup ? "Create your account" : "Sign in"}</h1>
        {signup && <p className="muted">Free plan: 10 scans a month. No card needed.</p>}
        <label className="field">Work email
          <input className="input" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={!!err} />
        </label>
        {signup && (
          <label className="field">Organization name <span className="muted" style={{ fontWeight: 400 }}>(optional)</span>
            <input className="input" autoComplete="organization" value={orgName} onChange={(e) => setOrgName(e.target.value)} maxLength={100} />
          </label>
        )}
        <label className="field">Password
          <input className="input" type="password" autoComplete={signup ? "new-password" : "current-password"} required minLength={signup ? 10 : 1} value={password} onChange={(e) => setPassword(e.target.value)} aria-invalid={!!err} aria-describedby={err ? "auth-err" : undefined} />
          {signup && <span className="muted" style={{ fontWeight: 400 }}>At least 10 characters.</span>}
        </label>
        {err && <div id="auth-err" className="err" role="alert">{err}</div>}
        <button className="btn primary lg" disabled={busy} aria-busy={busy}>{busy ? "Please wait…" : signup ? "Create account" : "Sign in"}</button>
        <p className="muted" style={{ textAlign: "center" }}>
          {signup ? <>Already have an account? <Link href="/signin">Sign in</Link></> : <>New here? <Link href="/signup">Create an account</Link></>}
        </p>
      </form>
    </div>
  );
}

export function InvitePage({ token, onDone }: { token: string; onDone: (m: Me) => void }) {
  const [, nav] = useLocation();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try { onDone(await api<Me>("POST", "/invites/accept", { token, password, name: name || undefined })); nav("/"); }
    catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  }
  return (
    <div className="auth">
      <form className="card" onSubmit={submit}>
        <Brand />
        <h1>Join your team</h1>
        <p className="muted">Choose a password for your account. If you already have one, enter it.</p>
        <label className="field">Your name <input className="input" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} /></label>
        <label className="field">Password <input className="input" type="password" autoComplete="new-password" required minLength={10} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {err && <div className="err" role="alert">{err}</div>}
        <button className="btn primary lg" disabled={busy}>{busy ? "Please wait…" : "Accept invitation"}</button>
      </form>
    </div>
  );
}
