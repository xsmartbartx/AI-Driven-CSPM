import { useState } from "react";
import { Link, useLocation, useSearch } from "wouter";
import { SAMPLE_CONFIG } from "@workspace/cspm-engine";
import { api, ApiError, useApi } from "../api";
import { useMe } from "../App";
import { Empty, ErrorBox, fmtTime, Kpi, Sev, Skeleton } from "../ui";

export function NewScan() {
  const { can } = useMe();
  const search = useSearch();
  const [, nav] = useLocation();
  const usage = useApi<any>("/usage");
  const [text, setText] = useState(() => (new URLSearchParams(search).get("sample") ? JSON.stringify(SAMPLE_CONFIG, null, 2) : ""));
  const [errs, setErrs] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  if (!can("analyst")) return <Empty title="You need analyst access to run scans">Ask an admin in your organization to change your role.</Empty>;

  async function run() {
    setErrs([]);
    let config: unknown;
    try { config = JSON.parse(text); } catch (e) { return setErrs([`That is not valid JSON: ${(e as Error).message}`]); }
    setBusy(true);
    try {
      const r = await api<any>("POST", "/scans", { config });
      nav(`/scans/${r.id}`);
    } catch (e) {
      const x = e as ApiError;
      setErrs(x.code === "invalid_config" ? x.message.split(/(?<=\.)\s+/) : [x.message]);
      if (x.code === "quota_exceeded") usage.reload();
    } finally { setBusy(false); }
  }
  const u = usage.data?.scans;
  const out = u && u.used >= u.limit;

  return (
    <>
      <div className="page-h"><div><h1>New scan</h1><p>Paste your resources as JSON. Nothing leaves your organization.</p></div>
        {u && <div style={{ minWidth: 200 }}><div className="muted" style={{ fontSize: 13 }}>{u.used} of {u.limit} scans used this month</div><div className="bar" style={{ marginTop: 4 }}><i style={{ width: `${Math.min(100, (u.used / u.limit) * 100)}%`, background: out ? "var(--danger)" : undefined }} /></div></div>}
      </div>
      {out && <div className="banner error" role="alert">You have used all scans on your plan this month. <Link href="/usage">See plans</Link></div>}
      <div className="grid g21">
        <section className="card" style={{ display: "grid", gap: 12 }}>
          <label className="field" htmlFor="cfg">Resources (JSON)</label>
          <textarea id="cfg" className="textarea" rows={22} spellCheck={false} placeholder={'{\n  "resources": [\n    { "type": "s3_bucket", "name": "my-bucket", "public_read": true }\n  ]\n}'} value={text} onChange={(e) => setText(e.target.value)} aria-invalid={errs.length > 0} aria-describedby={errs.length ? "scan-errs" : undefined} />
          {errs.length > 0 && <ul id="scan-errs" className="err" role="alert" style={{ margin: 0, paddingLeft: 18 }}>{errs.map((e, i) => <li key={i}>{e}</li>)}</ul>}
          <div className="row">
            <button className="btn primary" onClick={run} disabled={busy || !text.trim() || !!out} aria-busy={busy}>{busy ? "Scanning…" : "Run scan"}</button>
            <button className="btn" onClick={() => { setText(JSON.stringify(SAMPLE_CONFIG, null, 2)); setErrs([]); }}>Load sample</button>
            {text && <button className="btn ghost" onClick={() => { setText(""); setErrs([]); }}>Clear</button>}
          </div>
        </section>
        <aside className="card">
          <h2 className="h2">Supported resources</h2>
          <dl className="kv" style={{ gridTemplateColumns: "1fr", gap: 4 }}>
            <dt><code>s3_bucket</code></dt><dd className="muted">public_read, encrypted</dd>
            <dt><code>security_group</code></dt><dd className="muted">ingress: [{"{"} cidr, port {"}"}]</dd>
            <dt><code>iam_policy</code></dt><dd className="muted">statements: [{"{"} effect, actions, resources {"}"}]</dd>
            <dt><code>database</code></dt><dd className="muted">publicly_accessible, encrypted</dd>
          </dl>
          <p className="muted" style={{ marginTop: 12 }}>Add <code>environment</code> (production, staging, development) and <code>criticality</code> (1–10) to weight the risk score. Up to 500 resources per scan.</p>
        </aside>
      </div>
    </>
  );
}

export function Scans() {
  const { data, error, loading, reload } = useApi<any>("/scans");
  return (
    <>
      <div className="page-h"><div><h1>Scan history</h1><p>Every scan and what changed.</p></div></div>
      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="card"><Skeleton lines={5} h={20} /></div>}
      {data && data.items.length === 0 && <Empty title="No scans yet" action={<Link href="/scans/new" className="btn primary">Run a scan</Link>}>Your scans will be listed here with what was new and what got fixed.</Empty>}
      {data && data.items.length > 0 && (
        <div className="card scroll-x" style={{ padding: 0 }}>
          <table className="tbl">
            <thead><tr><th>When</th><th>By</th><th>Resources</th><th>Findings</th><th>New</th><th>Fixed</th><th>Score</th></tr></thead>
            <tbody>{data.items.map((s: any) => (
              <tr key={s.id}>
                <td><Link href={`/scans/${s.id}`} className="title">{fmtTime(s.createdAt)}</Link></td>
                <td className="muted">{s.createdBy ?? "API key"}</td><td>{s.resourceCount}</td><td>{s.findingCount}</td>
                <td>{s.counts?.new ?? 0}</td><td>{s.counts?.fixed ?? 0}</td><td><strong>{s.score}</strong></td>
              </tr>))}</tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function ScanDetail({ id }: { id: string }) {
  const { data: s, error, loading, reload } = useApi<any>(`/scans/${id}`);
  if (error) return <><Link href="/scans">← Scan history</Link><ErrorBox error={error} retry={reload} /></>;
  if (loading || !s) return <div className="card"><Skeleton lines={5} h={20} /></div>;
  return (
    <>
      <Link href="/scans">← Scan history</Link>
      <div className="page-h"><div><h1>Scan result</h1><p>{fmtTime(s.createdAt)} · {s.resourceCount} resources</p></div><Link href="/" className="btn">Go to overview</Link></div>
      <section className="grid g4">
        <Kpi label="Posture score" value={s.score} />
        <Kpi label="New findings" value={s.counts.new} tone={s.counts.new ? "down" : undefined} />
        <Kpi label="Fixed since last scan" value={s.counts.fixed} tone={s.counts.fixed ? "up" : undefined} />
        <Kpi label="Still open" value={s.counts.persisting} />
      </section>
      {s.findings.length === 0 ? <Empty title="No findings in this scan">Everything you described passed the checks.</Empty> : (
        <div className="card scroll-x" style={{ padding: 0 }}>
          <table className="tbl"><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Risk</th></tr></thead>
            <tbody>{s.findings.map((f: any) => (
              <tr key={f.id}><td><Sev s={f.severity} /></td><td><Link href={`/findings/${f.id}`} className="title">{f.title}</Link></td><td style={{ overflowWrap: "anywhere" }}>{f.assetName}</td><td><strong>{f.riskScore}</strong></td></tr>))}</tbody></table>
        </div>
      )}
    </>
  );
}
