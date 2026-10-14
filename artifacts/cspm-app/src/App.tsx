import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Link, Route, Router, Switch, useLocation } from "wouter";
import { api, ApiError } from "./api";
import { Icon, ICONS } from "./ui";
import { Overview } from "./pages/Overview";
import { Findings, FindingDetail } from "./pages/Findings";
import { NewScan, ScanDetail, Scans } from "./pages/Scans";
import { Assets, Compliance } from "./pages/Inventory";
import { Audit, Settings, Team, Usage } from "./pages/Admin";
import { Planned } from "./pages/Planned";
import { AuthPage, InvitePage } from "./pages/Auth";

export type Role = "owner" | "admin" | "analyst" | "viewer";
export interface Me { user: { id: string; email: string; name: string | null }; org: { id: string; name: string; plan: string }; role: Role }
interface Ctx { me: Me; setMe: (m: Me | null) => void; can: (min: Role) => boolean; toast: (m: string) => void }
const RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3, owner: 4 };
const C = createContext<Ctx>(null as never);
export const useMe = () => useContext(C);

function applyTheme(t: string) {
  const r = document.documentElement;
  if (t === "light" || t === "dark") r.setAttribute("data-theme", t); else r.removeAttribute("data-theme");
}
export function getTheme(): string { try { return localStorage.getItem("theme") ?? "system"; } catch { return "system"; } }
export function setTheme(t: string) { try { localStorage.setItem("theme", t); } catch { /* storage blocked */ } applyTheme(t); }
applyTheme(getTheme());

const NAV: { h?: string; to: string; label: string; icon: keyof typeof ICONS; min?: Role; soon?: boolean }[] = [
  { to: "/", label: "Overview", icon: "home" },
  { to: "/findings", label: "Findings", icon: "alert" },
  { to: "/assets", label: "Assets", icon: "box" },
  { to: "/compliance", label: "Compliance", icon: "check" },
  { h: "Scans", to: "/scans/new", label: "New scan", icon: "scan", min: "analyst" },
  { to: "/scans", label: "Scan history", icon: "history" },
  { h: "Coming", to: "/planned/attack-paths", label: "Attack paths", icon: "path", soon: true },
  { to: "/planned/ai", label: "AI Security Center", icon: "spark", soon: true },
  { to: "/planned/remediation", label: "Remediation", icon: "wrench", soon: true },
  { to: "/planned/integrations", label: "Cloud accounts", icon: "plug", soon: true },
  { h: "Organization", to: "/usage", label: "Usage & plan", icon: "card" },
  { to: "/team", label: "Team", icon: "users", min: "admin" },
  { to: "/audit", label: "Audit log", icon: "log", min: "admin" },
  { to: "/settings", label: "Settings", icon: "cog" },
];

function Shell({ children }: { children: ReactNode }) {
  const { me, can, setMe } = useMe();
  const [loc] = useLocation();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [loc]);
  const active = (to: string) => (to === "/" ? loc === "/" : to === "/scans" ? loc === "/scans" || /^\/scans\/(?!new)/.test(loc) : loc === to || loc.startsWith(to + "/"));
  return (
    <div className="app">
      <aside className={`side ${open ? "open" : ""}`} aria-label="Main navigation">
        <Link href="/" className="brand">
          <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="var(--accent)" /><path d="M16 6l8 3v7c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V9z" fill="none" stroke="var(--on-accent)" strokeWidth="2" /></svg>
          NEXORA CSPM
        </Link>
        <nav className="nav">
          {NAV.filter((n) => !n.min || can(n.min)).map((n) => (
            <div key={n.to}>
              {n.h && <div className="nav-h">{n.h}</div>}
              <Link href={n.to} aria-current={active(n.to) ? "page" : undefined}>
                <Icon d={ICONS[n.icon]} />{n.label}{n.soon && <span className="soon">Soon</span>}
              </Link>
            </div>
          ))}
        </nav>
      </aside>
      <div className="main">
        <header className="top">
          <button className="btn ghost menu-btn" aria-label="Open navigation" aria-expanded={open} onClick={() => setOpen(!open)}><Icon d={ICONS.menu} /></button>
          <div className="grow"><strong>{me.org.name}</strong> <span className="chip" style={{ marginLeft: 8 }}>{me.org.plan}</span></div>
          <span className="muted" style={{ fontSize: 13 }}>{me.user.email} · {me.role}</span>
          <button className="btn sm" onClick={async () => { await api("POST", "/auth/logout").catch(() => {}); setMe(null); }}>Sign out</button>
        </header>
        <main className="content" id="main">{children}</main>
      </div>
    </div>
  );
}

export function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [toastMsg, setToast] = useState("");
  const [loadErr, setLoadErr] = useState<ApiError | null>(null);

  const boot = useCallback(() => {
    setLoadErr(null);
    api<Me>("GET", "/auth/me").then(setMe).catch((e: ApiError) => { if (e.status === 401) setMe(null); else setLoadErr(e); });
  }, []);
  useEffect(boot, [boot]);

  const toast = useCallback((m: string) => { setToast(m); setTimeout(() => setToast(""), 3000); }, []);

  if (loadErr) return <div className="auth"><div className="card" role="alert"><h1>Can’t reach the server</h1><p className="muted">{loadErr.message}</p><button className="btn primary" onClick={boot}>Try again</button></div></div>;
  if (me === undefined) return <div className="auth" aria-busy="true"><div className="skel" style={{ width: 240, height: 24 }} /></div>;

  return (
    <Router>
      <Switch>
        <Route path="/invite/:token">{(p) => <InvitePage token={p.token} onDone={setMe} />}</Route>
        {!me ? (
          <Route><AuthPage onAuth={setMe} /></Route>
        ) : (
          <Route>
            <C.Provider value={{ me, setMe, can: (min) => RANK[me.role] >= RANK[min], toast }}>
              <Shell>
                <Switch>
                  <Route path="/" component={Overview} />
                  <Route path="/findings" component={Findings} />
                  <Route path="/findings/:id">{(p) => <FindingDetail id={p.id} />}</Route>
                  <Route path="/scans/new" component={NewScan} />
                  <Route path="/scans" component={Scans} />
                  <Route path="/scans/:id">{(p) => <ScanDetail id={p.id} />}</Route>
                  <Route path="/assets" component={Assets} />
                  <Route path="/compliance" component={Compliance} />
                  <Route path="/usage" component={Usage} />
                  <Route path="/team" component={Team} />
                  <Route path="/audit" component={Audit} />
                  <Route path="/settings" component={Settings} />
                  <Route path="/planned/:name">{(p) => <Planned name={p.name} />}</Route>
                  <Route><div className="card empty"><h2>Page not found</h2><Link href="/" className="btn primary">Back to overview</Link></div></Route>
                </Switch>
              </Shell>
              {toastMsg && <div className="toast" role="status" aria-live="polite">{toastMsg}</div>}
            </C.Provider>
          </Route>
        )}
      </Switch>
    </Router>
  );
}
