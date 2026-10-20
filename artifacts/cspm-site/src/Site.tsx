import { useState } from "react";
import { Link, Route, Router, Switch, useLocation } from "wouter";
import { SAMPLE_CONFIG } from "@workspace/cspm-engine";

// Where the signed-in product lives. In production: https://app.cspm.onenexora.com
const APP = ((import.meta as any).env?.VITE_APP_URL as string | undefined) ?? "http://localhost:5174";
const API = ((import.meta as any).env?.VITE_API_URL ?? "") + "/api";

const PLANS = [
  { id: "free", name: "Free", price: "$0", note: "10 scans a month", pts: ["All rule checks", "Findings with fixes", "1 organization"], cta: "Start free", hl: false },
  { id: "starter", name: "Starter", price: "$19", note: "75 scans a month", pts: ["Everything in Free", "AI explanations", "Team roles and audit log", "API keys"], cta: "Start with Starter", hl: true },
  { id: "team", name: "Team", price: "$79", note: "500 scans a month", pts: ["Everything in Starter", "Higher AI allowance", "Priority support"], cta: "Contact us", hl: false },
  { id: "ent", name: "Enterprise", price: "Custom", note: "Your limits", pts: ["Single sign-on", "Custom limits", "Security review"], cta: "Contact us", hl: false },
];

function Nav() {
  const [loc] = useLocation();
  const cur = (p: string) => (loc === p ? "page" : undefined);
  return (
    <header className="nav">
      <div className="wrap">
        <Link href="/" className="brand">
          <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="var(--accent)" /><path d="M16 6l8 3v7c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V9z" fill="none" stroke="var(--on-accent)" strokeWidth="2" /></svg>
          <span className="brand-text">NEXORA CSPM</span>
        </Link>
        <nav className="row" style={{ gap: 16 }} aria-label="Site">
          <Link href="/" className="link" aria-current={cur("/")}>Product</Link>
          <Link href="/pricing" className="link" aria-current={cur("/pricing")}>Pricing</Link>
          <Link href="/docs" className="link" aria-current={cur("/docs")}>Docs</Link>
        </nav>
        <span className="grow" />
        <a className="link hide-s" href={`${APP}/signin`}>Sign in</a>
        <a className="btn primary" href={`${APP}/signup`}>Start free</a>
      </div>
    </header>
  );
}

function Demo() {
  const [text, setText] = useState(JSON.stringify(SAMPLE_CONFIG, null, 2));
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function scan() {
    setErr(""); setBusy(true);
    try {
      let config: unknown;
      try { config = JSON.parse(text); } catch (e) { throw new Error(`That is not valid JSON: ${(e as Error).message}`); }
      const r = await fetch(`${API}/demo/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ config }) });
      const j = await r.json().catch(() => null);
      if (!r.ok) throw new Error(j?.error?.message ?? (r.status === 429 ? "Demo limit reached. Create a free account to keep scanning." : "The demo is unavailable right now. Try again shortly."));
      setRes(j);
    } catch (e) { setErr((e as Error).message); setRes(null); } finally { setBusy(false); }
  }
  return (
    <div className="demo">
      <div className="card" style={{ display: "grid", gap: 12 }}>
        <label className="field" htmlFor="demo-cfg">Your resources (JSON)</label>
        <textarea id="demo-cfg" className="textarea" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} />
        <div className="row"><button className="btn primary" onClick={scan} disabled={busy || !text.trim()} aria-busy={busy}>{busy ? "Scanning…" : "Scan"}</button><span className="muted">Nothing is stored in the demo.</span></div>
      </div>
      <div className="card res" aria-live="polite">
        {err && <div className="err" role="alert">{err}</div>}
        {!res && !err && <p className="muted">Press Scan to see ranked findings for this sample.</p>}
        {res && (
          <>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <div><div className="muted">Posture score</div><div className="score">{res.score}<span className="muted" style={{ fontSize: 18 }}>/100</span></div></div>
              <div className="muted" style={{ textAlign: "right" }}>{res.resourceCount} resources<br />{res.findings.length} findings</div>
            </div>
            {res.unknownTypes.length > 0 && <div className="banner">Not checked (unsupported type): {res.unknownTypes.join(", ")}</div>}
            {res.findings.slice(0, 5).map((f: any, i: number) => (
              <div className="finding" key={i}>
                <div className="row" style={{ justifyContent: "space-between" }}><span className={`chip ${f.severity}`}>{f.severity[0].toUpperCase() + f.severity.slice(1)}</span><strong>Risk {f.riskScore}</strong></div>
                <div className="title" style={{ fontWeight: 600 }}>{f.title}</div>
                <div className="muted" style={{ overflowWrap: "anywhere" }}>{f.resourceName}</div>
                <div style={{ fontSize: 13 }}>{f.remediation}</div>
              </div>
            ))}
            {res.findings.length > 5 && <p className="muted">+ {res.findings.length - 5} more. <a href={`${APP}/signup`}>Create a free account</a> to see all, track fixes and watch your score over time.</p>}
            {res.findings.length === 0 && <p>No findings. Everything you described passed.</p>}
          </>
        )}
      </div>
    </div>
  );
}

function Home() {
  return (
    <>
      <section className="hero"><div className="wrap">
        <span className="chip eyebrow">Beta</span>
        <h1>Find cloud misconfigurations in seconds.</h1>
        <p className="lead">Paste your cloud configuration. Get a short list ranked by risk, each with the fix. Free to start, public prices, no sales call.</p>
        <div className="cta"><a className="btn primary lg" href={`${APP}/signup`}>Start free</a><a className="btn lg" href="#try">Try it now</a></div>
        <p className="muted" style={{ marginTop: 16 }}>Free plan: 10 scans a month. No card needed.</p>
      </div></section>

      <section className="block alt"><div className="wrap">
        <h2 className="sec">From config to fix in three steps</h2>
        <div className="steps">
          {[["Describe", "List your buckets, security groups, IAM policies and databases as JSON."], ["Scan", "A rule set checks every resource and scores the risk by how critical the asset is."], ["Fix", "Each finding comes with the evidence, the reason it matters and what to change."]].map(([t, d], i) => (
            <div className="step card" key={t}><div className="n">{i + 1}</div><h3>{t}</h3><p>{d}</p></div>
          ))}
        </div>
      </div></section>

      <section className="block" id="try"><div className="wrap">
        <h2 className="sec">Try it with a sample</h2>
        <p className="sub">Edit the JSON or run it as is. This is the same engine your dashboard uses.</p>
        <Demo />
      </div></section>

      <section className="block alt"><div className="wrap">
        <h2 className="sec">What it checks today</h2>
        <div className="rules">
          {[["Storage", "Public read access and missing encryption at rest."], ["Network", "Admin and database ports open to the internet, and security groups that allow all traffic."], ["Identity", "Policies that grant administrator access, wildcard actions or wildcard resources."], ["Databases", "Public accessibility and missing encryption at rest."]].map(([t, d]) => (
            <div className="card" key={t}><h3 className="h2" style={{ marginBottom: 4 }}>{t}</h3><p className="muted">{d}</p></div>
          ))}
        </div>
        <p className="honest">Paste-your-config is the supported way to scan today. Connecting a live AWS account (read-only role, no keys stored) is built but still being tested against real accounts, so it is not switched on yet. Attack paths and generated fixes are on the roadmap. We would rather say so than show a screenshot of something that does not exist yet.</p>
      </div></section>

      <section className="block"><div className="wrap">
        <h2 className="sec">For the whole team</h2>
        <p className="sub">A dashboard that answers “how are we doing?” for managers and “what do I fix first?” for engineers.</p>
        <div className="rules">
          {[["Posture score and trend", "One number, its change over 30 days, 3 months or 6 months."], ["Prioritised findings", "Sorted by risk, filterable by severity, resource and status. Accept a risk with a reason and an expiry."], ["Compliance view", "See how open findings map to CIS, PCI DSS, NIST 800-53, ISO 27001 and GDPR controls."], ["Roles, audit log, API", "Owner, admin, analyst and viewer roles, a record of changes, and API keys for your pipeline."]].map(([t, d]) => (
            <div className="card" key={t}><h3 className="h2" style={{ marginBottom: 4 }}>{t}</h3><p className="muted">{d}</p></div>
          ))}
        </div>
      </div></section>
    </>
  );
}

function Pricing() {
  return (
    <section className="block"><div className="wrap">
      <h1 className="sec">Simple pricing</h1>
      <p className="sub">Start free. Pay when you need more scans.</p>
      <div className="price-grid">
        {PLANS.map((p) => (
          <section key={p.id} className={`card plan ${p.hl ? "hl" : ""}`} aria-labelledby={`p-${p.id}`}>
            <h2 className="h2" id={`p-${p.id}`} style={{ margin: 0 }}>{p.name}</h2>
            <div className="price">{p.price}{p.price.startsWith("$") && p.price !== "$0" && <small>/month</small>}</div>
            <div className="muted">{p.note}</div>
            <ul className="ticks">{p.pts.map((x) => <li key={x}>{x}</li>)}</ul>
            {p.id === "free" || p.id === "starter" ? <a className={`btn ${p.hl ? "primary" : ""}`} href={`${APP}/signup`}>{p.cta}</a> : <a className="btn" href="mailto:sales@onenexora.com?subject=NEXORA%20CSPM">{p.cta}</a>}
          </section>
        ))}
      </div>
      <h2 className="h2" style={{ marginTop: 48 }}>Questions</h2>
      <div className="grid" style={{ display: "grid", gap: 16, maxWidth: 720 }}>
        <div><strong>What counts as a scan?</strong><p className="muted">Each time you submit a configuration to be checked in your dashboard or through the API. The demo on the home page is free and not counted.</p></div>
        <div><strong>What happens at the limit?</strong><p className="muted">New scans pause until the 1st of next month or until you upgrade. Existing findings stay available.</p></div>
        <div><strong>Is my data used for training?</strong><p className="muted">No. Your configuration is stored in your organization only, and visible only to its members.</p></div>
      </div>
    </div></section>
  );
}

const DRAFT = "Draft. Not yet reviewed by a lawyer. Replace the bracketed details before launch.";
function Privacy() {
  return (
    <section className="block docs"><div className="wrap" style={{ maxWidth: 760 }}>
      <h1 className="sec">Privacy</h1>
      <p className="banner">{DRAFT}</p>
      <h3>What we collect</h3>
      <p>Account details (email, name, password hash), your organization’s members and roles, the configurations you submit and the findings we derive from them, usage counts, and an audit log of actions in your organization. We also keep standard server logs (time, path, status, IP address) for security and debugging. Request logs do not include query strings or request bodies.</p>
      <h3>What we do with it</h3>
      <p>We run the scans you ask for, show you the results, enforce plan limits, secure the service and bill you. We do not sell your data and do not use your configurations to train models.</p>
      <h3>Who processes it</h3>
      <ul><li>Hosting and database provider: [name, region]</li><li>If you connect an AWS account: we read configuration metadata (bucket settings, security group rules, IAM policy documents, database settings) with a read-only role you create. We never read bucket contents, database contents or secrets, and we keep no AWS keys, only a short-lived session (15 minutes) that is requested when you verify a connection or run a scan. The metadata is stored in your organization like any scan result.</li><li>Payments: Stripe (card details go to Stripe, never to us)</li><li>Optional AI explanations: if enabled, the finding text and resource names are sent to Anthropic to write the explanation. Without it, explanations are generated by rules inside our service.</li><li>Email delivery (account confirmation, password reset, invitations): Resend. It receives the recipient address and the message.</li></ul>
      <h3>Your choices</h3>
      <p>You can export findings as CSV, sign out on all devices, and delete your account from Settings. Deleting your account removes your data; if you were the only member, the organization’s data is deleted too. Backups may keep copies for up to [30] days. For other requests write to [privacy contact].</p>
      <h3>Retention and security</h3>
      <p>Passwords are hashed. Sessions are cookies that JavaScript cannot read. Access to each organization’s data is restricted to its members. [Retention periods]. [Data location and transfers.]</p>
    </div></section>
  );
}
function Terms() {
  return (
    <section className="block docs"><div className="wrap" style={{ maxWidth: 760 }}>
      <h1 className="sec">Terms</h1>
      <p className="banner">{DRAFT}</p>
      <h3>The service</h3>
      <p>NEXORA CSPM checks configuration you submit against a set of rules and reports findings. It is in beta and provided as is. It is not a security audit, a compliance certification or legal advice. Control references are indicative mappings, not an audit result.</p>
      <h3>Your responsibilities</h3>
      <p>Only submit configuration you are allowed to share. Do not put secrets, keys or personal data in submitted configs. Do not probe, overload or attack the service.</p>
      <h3>Plans, billing and cancellation</h3>
      <p>Free and paid plans have monthly scan limits, shown on the pricing page. Paid plans renew monthly until cancelled; you can cancel from the billing portal at any time and keep access until the period ends. [Refund terms.]</p>
      <h3>Liability</h3>
      <p>[To be written by counsel: warranty disclaimer, liability cap, governing law.]</p>
      <h3>Changes</h3>
      <p>We will tell you about material changes before they apply. [Contact.]</p>
    </div></section>
  );
}

function Docs() {
  return (
    <section className="block docs"><div className="wrap" style={{ maxWidth: 800 }}>
      <h1 className="sec">Quickstart</h1>
      <p className="sub">Describe resources, scan, read the findings.</p>
      <h3>1. Describe your resources</h3>
      <p>A JSON array, or an object with a <code>resources</code> array. Every item needs a <code>type</code> and a unique <code>name</code>. Add <code>environment</code> and <code>criticality</code> (1–10) to weight the risk.</p>
      <pre className="code">{JSON.stringify({ resources: SAMPLE_CONFIG.resources.slice(0, 3) }, null, 2)}</pre>
      <h3>2. Supported types</h3>
      <ul>
        <li><code>s3_bucket</code>: <code>public_read</code>, <code>encrypted</code></li>
        <li><code>security_group</code>: <code>ingress</code> list of <code>{"{ cidr, port }"}</code> (port can be a number or <code>"all"</code>)</li>
        <li><code>iam_policy</code>: <code>statements</code> list of <code>{"{ effect, actions, resources }"}</code></li>
        <li><code>database</code>: <code>publicly_accessible</code>, <code>encrypted</code></li>
      </ul>
      <h3>3. Scan</h3>
      <p>Paste into <em>New scan</em> in the dashboard, or call the API with a key from <em>Settings</em>:</p>
      <pre className="code">{`curl -X POST https://api.cspm.onenexora.com/api/scans \\
  -H "Authorization: Bearer cspm_…" \\
  -H "Content-Type: application/json" \\
  -d '{"config": {"resources": [...]}}'`}</pre>
      <h3>How the risk score works</h3>
      <p>Each rule has a base score from 0 to 100. It is scaled by the asset’s criticality (default 5, or 8 for production). 76 and above is critical, 51–75 high, 21–50 medium. Your posture score starts at 100 and drops for every open finding, more for severe ones. Threat intelligence and network reachability are not used yet because a pasted configuration does not contain them.</p>
      <h3>Limits</h3>
      <p>500 resources and 1 MB per scan. Plan quotas apply per calendar month (UTC).</p>
    </div></section>
  );
}

export function Site() {
  return (
    <Router>
      <a href="#main" className="sr-only">Skip to content</a>
      <Nav />
      <main id="main">
        <Switch>
          <Route path="/" component={Home} />
          <Route path="/pricing" component={Pricing} />
          <Route path="/docs" component={Docs} />
          <Route path="/privacy" component={Privacy} />
          <Route path="/terms" component={Terms} />
          <Route><section className="block"><div className="wrap"><h1 className="sec">Page not found</h1><Link href="/" className="btn primary">Back home</Link></div></section></Route>
        </Switch>
      </main>
      <footer><div className="wrap">
        <span>© NEXORA. CSPM is in beta.</span>
        <span className="row" style={{ gap: 16 }}><a href="https://onenexora.com">NEXORA</a><a href="https://status.onenexora.com">Status</a><Link href="/docs">Docs</Link><Link href="/privacy">Privacy</Link><Link href="/terms">Terms</Link></span>
      </div></footer>
    </Router>
  );
}
