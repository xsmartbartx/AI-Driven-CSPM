import { useEffect, useState, type FormEvent } from "react";
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
        {!signup && <p style={{ textAlign: "center" }}><Link href="/forgot-password">Forgot your password?</Link></p>}
        <p className="muted" style={{ textAlign: "center" }}>
          {signup ? <>Already have an account? <Link href="/signin">Sign in</Link></> : <>New here? <Link href="/signup">Create an account</Link></>}
        </p>
      </form>
    </div>
  );
}

export function InvitePage({ token, onDone, signedInSso }: { token: string; onDone: (m: Me) => void; signedInSso: string | null }) {
  const [, nav] = useLocation();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try { onDone(await api<Me>("POST", "/invites/accept", { token, password: signedInSso ? undefined : password, name: name || undefined })); nav("/"); }
    catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  }
  return (
    <div className="auth">
      <form className="card" onSubmit={submit}>
        <Brand />
        <h1>Join your team</h1>
        {signedInSso ? <p className="muted">You are signed in as {signedInSso} through NEXORA. Accept to join this organization.</p> : (
          <>
            <p className="muted">Choose a password for your account. If you already have one, enter it.</p>
            <label className="field">Your name <input className="input" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} /></label>
            <label className="field">Password <input className="input" type="password" autoComplete="new-password" required minLength={10} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          </>
        )}
        {err && <div className="err" role="alert">{err}</div>}
        <button className="btn primary lg" disabled={busy}>{busy ? "Please wait…" : "Accept invitation"}</button>
      </form>
    </div>
  );
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [done, setDone] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try { await api("POST", "/auth/forgot-password", { email }); setDone(true); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  }
  return (
    <div className="auth">
      <form className="card" onSubmit={submit}>
        <Brand />
        <h1>Reset your password</h1>
        {done ? (
          <div className="banner" role="status">If an account exists for {email}, we have sent a link to choose a new password. It works for one hour. Check your spam folder if it does not arrive.</div>
        ) : (
          <>
            <p className="muted">Enter your email and we will send you a link.</p>
            <label className="field">Email<input className="input" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
            {err && <div className="err" role="alert">{err}</div>}
            <button className="btn primary lg" disabled={busy} aria-busy={busy}>{busy ? "Please wait…" : "Send reset link"}</button>
          </>
        )}
        <p style={{ textAlign: "center" }}><Link href="/signin">Back to sign in</Link></p>
      </form>
    </div>
  );
}

export function ResetPasswordPage({ token }: { token: string }) {
  const [password, setPassword] = useState("");
  const [done, setDone] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try { await api("POST", "/auth/reset-password", { token, password }); setDone(true); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  }
  return (
    <div className="auth">
      <form className="card" onSubmit={submit}>
        <Brand />
        <h1>Choose a new password</h1>
        {done ? (
          <>
            <div className="banner" role="status">Your password is changed and you are signed out everywhere.</div>
            <Link href="/signin" className="btn primary lg">Sign in</Link>
          </>
        ) : (
          <>
            <label className="field">New password<input className="input" type="password" autoComplete="new-password" required minLength={10} value={password} onChange={(e) => setPassword(e.target.value)} aria-describedby="pw-hint" />
              <span id="pw-hint" className="muted" style={{ fontWeight: 400 }}>At least 10 characters.</span></label>
            {err && <div className="err" role="alert">{err} {err.includes("invalid or has expired") && <Link href="/forgot-password">Send a new link</Link>}</div>}
            <button className="btn primary lg" disabled={busy} aria-busy={busy}>{busy ? "Please wait…" : "Change password"}</button>
          </>
        )}
      </form>
    </div>
  );
}

export function VerifyEmailPage({ token }: { token: string }) {
  const [state, setState] = useState<"working" | "ok" | "bad">("working");
  const [msg, setMsg] = useState("");
  useEffect(() => {
    let alive = true;
    api("POST", "/auth/verify-email", { token }).then(() => alive && setState("ok")).catch((x: ApiError) => { if (alive) { setMsg(x.message); setState("bad"); } });
    return () => { alive = false; };
  }, [token]);
  return (
    <div className="auth">
      <div className="card" role="status" aria-live="polite">
        <Brand />
        {state === "working" && <p>Confirming your email…</p>}
        {state === "ok" && <><h1>Email confirmed</h1><p className="muted">Thanks. You can close this tab or continue.</p><Link href="/" className="btn primary lg">Open the dashboard</Link></>}
        {state === "bad" && <><h1>That link did not work</h1><p className="err" role="alert">{msg}</p><p className="muted">Sign in and use “Resend” in the banner to get a new link.</p><Link href="/signin" className="btn lg">Sign in</Link></>}
      </div>
    </div>
  );
}
