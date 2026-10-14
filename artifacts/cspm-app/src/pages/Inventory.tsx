import { useState } from "react";
import { Link, useSearch } from "wouter";
import { useApi } from "../api";
import { Empty, ErrorBox, fmtDate, Skeleton } from "../ui";

const TYPE_LABEL: Record<string, string> = { s3_bucket: "Storage bucket", security_group: "Security group", iam_policy: "IAM policy", database: "Database" };

export function Assets() {
  const type = new URLSearchParams(useSearch()).get("type") ?? "";
  const [q, setQ] = useState("");
  const qs = new URLSearchParams(); if (type) qs.set("type", type); if (q) qs.set("q", q);
  const { data, error, loading, reload } = useApi<any>(`/assets?${qs}`);
  return (
    <>
      <div className="page-h"><div><h1>Assets</h1><p>Everything your scans have seen.</p></div></div>
      <div className="card row">
        <input className="input" style={{ maxWidth: 280 }} type="search" placeholder="Search by name" aria-label="Search assets" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="row" role="group" aria-label="Resource type" style={{ gap: 6 }}>
          <Link href="/assets" className={`btn sm ${type ? "" : "primary"}`}>All</Link>
          {data?.types.map((t: any) => <Link key={t.type} href={`/assets?type=${t.type}`} className={`btn sm ${type === t.type ? "primary" : ""}`}>{TYPE_LABEL[t.type] ?? t.type} · {t.n}</Link>)}
        </div>
      </div>
      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="card"><Skeleton lines={6} h={20} /></div>}
      {data && data.items.length === 0 && <Empty title={q || type ? "No assets match" : "No assets yet"} action={!q && !type ? <Link href="/scans/new" className="btn primary">Run a scan</Link> : undefined}>{q || type ? "Try a different search." : "Assets appear here after your first scan."}</Empty>}
      {data && data.items.length > 0 && (
        <div className="card scroll-x" style={{ padding: 0 }}>
          <table className="tbl">
            <thead><tr><th>Name</th><th>Type</th><th>Environment</th><th>Criticality</th><th>Open findings</th><th>Highest risk</th><th>Last seen</th></tr></thead>
            <tbody>{data.items.map((a: any) => (
              <tr key={a.id}>
                <td style={{ overflowWrap: "anywhere" }}><strong>{a.name}</strong></td><td>{TYPE_LABEL[a.type] ?? a.type}</td><td>{a.environment}</td><td>{a.criticality}/10</td>
                <td>{a.openFindings ? <Link href={`/findings?q=${encodeURIComponent(a.name)}`}>{a.openFindings}</Link> : <span className="chip ok">None</span>}</td>
                <td>{a.maxRisk || "–"}</td><td className="muted">{fmtDate(a.lastSeenAt)}</td>
              </tr>))}</tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function Compliance() {
  const { data, error, loading, reload } = useApi<any>("/compliance");
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      <div className="page-h"><div><h1>Compliance</h1><p>How your open findings map to common frameworks.</p></div></div>
      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="card"><Skeleton lines={6} h={20} /></div>}
      {data && (
        <>
          <div className="banner">{data.note}</div>
          <div className="grid g3">
            {data.frameworks.map((f: any) => (
              <section key={f.framework} className="card" aria-labelledby={`fw-${f.framework}`}>
                <div className="row" style={{ justifyContent: "space-between" }}><h2 className="h2" id={`fw-${f.framework}`} style={{ margin: 0 }}>{f.framework}</h2><strong style={{ fontSize: 22 }}>{f.coverage}%</strong></div>
                <div className="bar" style={{ margin: "10px 0" }}><i style={{ width: `${f.coverage}%`, background: f.coverage >= 90 ? "var(--success)" : f.coverage >= 70 ? "var(--warning)" : "var(--danger)" }} /></div>
                <div className="muted">{f.controls - f.failed} of {f.controls} mapped controls passing. Not a full {f.framework} assessment.</div>
                {f.failed > 0 && (
                  <>
                    <button className="btn sm" style={{ marginTop: 12 }} aria-expanded={open === f.framework} onClick={() => setOpen(open === f.framework ? null : f.framework)}>{open === f.framework ? "Hide" : "Show"} failing controls</button>
                    {open === f.framework && (
                      <ul className="list" style={{ listStyle: "none", padding: 0, margin: "12px 0 0" }}>
                        {f.failedControls.map((c: any) => (
                          <li key={c.control}><strong>{c.control}</strong><div className="muted">{c.ruleIds.map((id: string) => data.ruleTitles[id] ?? id).join("; ")}</div>
                            <Link href={`/findings?q=${encodeURIComponent(data.ruleTitles[c.ruleIds[0]] ?? "")}`}>View findings</Link></li>))}
                      </ul>
                    )}
                  </>
                )}
              </section>
            ))}
          </div>
        </>
      )}
    </>
  );
}
