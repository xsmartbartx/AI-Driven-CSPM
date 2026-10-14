import { Fragment, useEffect, useState, type FormEvent } from "react";
import { Link, useLocation, useSearch } from "wouter";
import { api, apiUrl, ApiError, useApi } from "../api";
import { useMe } from "../App";
import { Dialog, Empty, ErrorBox, fmtDate, Sev, Skeleton, Status, STATUS_LABEL } from "../ui";

export function Findings() {
  const search = useSearch();
  const [, nav] = useLocation();
  const params = new URLSearchParams(search);
  const [q, setQ] = useState(params.get("q") ?? "");
  const severity = params.get("severity") ?? "";
  const status = params.get("status") ?? "open";
  const type = params.get("type") ?? "";
  const page = Number(params.get("page") ?? 1);

  const set = (k: string, v: string) => {
    const p = new URLSearchParams(search);
    if (v) p.set(k, v); else p.delete(k);
    if (k !== "page") p.delete("page");
    nav("/findings" + (p.toString() ? `?${p}` : ""), { replace: true });
  };
  // debounce the search box into the URL
  useEffect(() => {
    const t = setTimeout(() => { if (q !== (params.get("q") ?? "")) set("q", q); }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);

  const qs = new URLSearchParams({ status, page: String(page), pageSize: "25" });
  if (severity) qs.set("severity", severity);
  if (type) qs.set("type", type);
  if (params.get("q")) qs.set("q", params.get("q")!);
  const { data, error, loading, reload } = useApi<any>(`/findings?${qs}`);
  const pages = data ? Math.max(1, Math.ceil(data.total / data.pageSize)) : 1;

  return (
    <>
      <div className="page-h">
        <div><h1>Findings</h1><p>Misconfigurations ranked by business risk.</p></div>
        <a className="btn" href={apiUrl("/reports/summary.csv")}>Export CSV</a>
      </div>
      <div className="card row" role="search" aria-label="Filter findings">
        <input className="input" style={{ maxWidth: 280 }} type="search" placeholder="Search title or asset" aria-label="Search findings" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="select" style={{ width: 150 }} aria-label="Severity" value={severity} onChange={(e) => set("severity", e.target.value)}>
          <option value="">All severities</option>{["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s[0]!.toUpperCase() + s.slice(1)}</option>)}
        </select>
        <select className="select" style={{ width: 170 }} aria-label="Status" value={status} onChange={(e) => set("status", e.target.value)}>
          {["open", "accepted", "false_positive", "fixed", "all"].map((s) => <option key={s} value={s}>{s === "all" ? "Any status" : STATUS_LABEL[s]}</option>)}
        </select>
        <select className="select" style={{ width: 170 }} aria-label="Resource type" value={type} onChange={(e) => set("type", e.target.value)}>
          <option value="">All resource types</option>
          {[["s3_bucket", "Storage buckets"], ["security_group", "Security groups"], ["iam_policy", "IAM policies"], ["database", "Databases"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      </div>

      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="card"><Skeleton lines={6} h={20} /></div>}
      {data && data.items.length === 0 && (
        <Empty title={search ? "No findings match these filters" : "No findings yet"}>
          {search ? "Try removing a filter." : "Run a scan to see findings here."}
        </Empty>
      )}
      {data && data.items.length > 0 && (
        <div className="card scroll-x" style={{ padding: 0 }}>
          <table className="tbl">
            <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Risk</th><th>Status</th><th>First seen</th></tr></thead>
            <tbody>
              {data.items.map((f: any) => (
                <tr key={f.id}>
                  <td><Sev s={f.severity} /></td>
                  <td><Link href={`/findings/${f.id}`} className="title">{f.title}</Link></td>
                  <td style={{ overflowWrap: "anywhere" }}>{f.assetName}<div className="muted">{f.assetType.replace("_", " ")} · {f.environment}</div></td>
                  <td><strong>{f.riskScore}</strong></td>
                  <td><Status s={f.status} /></td>
                  <td className="muted">{fmtDate(f.firstSeenAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && data.total > data.pageSize && (
        <nav className="row" aria-label="Pagination" style={{ justifyContent: "center" }}>
          <button className="btn" disabled={page <= 1} onClick={() => set("page", String(page - 1))}>Previous</button>
          <span className="muted">Page {page} of {pages} · {data.total} findings</span>
          <button className="btn" disabled={page >= pages} onClick={() => set("page", String(page + 1))}>Next</button>
        </nav>
      )}
    </>
  );
}

export function FindingDetail({ id }: { id: string }) {
  const { can, toast } = useMe();
  const { data: f, error, loading, reload } = useApi<any>(`/findings/${id}`);
  const [dlg, setDlg] = useState<null | "accepted" | "false_positive">(null);
  const [busy, setBusy] = useState(false);
  const [aiErr, setAiErr] = useState("");
  const [brief, setBrief] = useState<any>(null);
  useEffect(() => { if (f?.brief) setBrief(f.brief); }, [f]);

  if (error) return <><Link href="/findings">← Findings</Link><ErrorBox error={error} retry={reload} /></>;
  if (loading || !f) return <div className="card"><Skeleton lines={6} h={20} /></div>;

  async function explain(refresh = false) {
    setBusy(true); setAiErr("");
    try { setBrief(await api("POST", `/findings/${id}/explain`, { refresh })); } catch (e) { setAiErr((e as ApiError).message); } finally { setBusy(false); }
  }
  async function setStatus(body: object) {
    try { await api("PATCH", `/findings/${id}`, body); toast("Status updated"); setDlg(null); reload(); }
    catch (e) { throw e; }
  }
  const editable = can("analyst") && f.status !== "fixed";

  return (
    <>
      <Link href="/findings">← Findings</Link>
      <div className="page-h">
        <div>
          <div className="row"><Sev s={f.severity} /><Status s={f.status} /></div>
          <h1 style={{ marginTop: 8 }}>{f.title}</h1>
          <p style={{ overflowWrap: "anywhere" }}>{f.assetType.replace("_", " ")} <strong>{f.assetName}</strong> · {f.environment}</p>
        </div>
        {editable && (
          <div className="row">
            {f.status === "open" ? (
              <>
                <button className="btn" onClick={() => setDlg("accepted")}>Accept risk</button>
                <button className="btn" onClick={() => setDlg("false_positive")}>Mark false positive</button>
              </>
            ) : <button className="btn" onClick={() => setStatus({ status: "open" }).catch((e) => toast((e as ApiError).message))}>Reopen</button>}
          </div>
        )}
      </div>

      {f.status === "accepted" && <div className="banner">Accepted until {fmtDate(f.acceptedUntil)}. Reason: {f.statusReason}</div>}
      {f.status === "false_positive" && <div className="banner">Marked as a false positive. Reason: {f.statusReason}</div>}
      {f.status === "fixed" && <div className="banner">This finding no longer appears in your latest scan, so it is marked fixed.</div>}

      <div className="grid g21">
        <div className="grid">
          <section className="card" aria-labelledby="ev"><h2 className="h2" id="ev">What we found</h2>
            <dl className="kv">{Object.entries(f.evidence).map(([k, v]) => <Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd></Fragment>)}</dl>
          </section>
          <section className="card" aria-labelledby="fix"><h2 className="h2" id="fix">How to fix</h2><p>{f.remediation}</p></section>
          <section className="card" aria-labelledby="ai">
            <div className="row" style={{ justifyContent: "space-between" }}>
              <h2 className="h2" id="ai" style={{ margin: 0 }}>Explanation</h2>
              {can("analyst") && <button className="btn sm" onClick={() => explain(!!brief)} disabled={busy} aria-busy={busy}>{busy ? "Working…" : brief ? "Regenerate" : "Explain this finding"}</button>}
            </div>
            {aiErr && <div className="err" role="alert" style={{ marginTop: 8 }}>{aiErr}</div>}
            {brief ? (
              <>
                <p className="pre" style={{ marginTop: 12 }}>{brief.content}</p>
                <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>{brief.model === "rules" ? "Written from the scanner’s rule and your config only." : `Generated by ${brief.model} from the scanner’s rule and your config. Check before acting.`}</p>
              </>
            ) : <p className="muted" style={{ marginTop: 12 }}>{f.ruleExplanation.split("\n\n").slice(0, 2).join(" ")}</p>}
          </section>
        </div>
        <aside className="grid" style={{ alignContent: "start" }}>
          <section className="card" aria-labelledby="rk"><h2 className="h2" id="rk">Risk</h2>
            <div className="kpi"><div className="value">{f.riskScore}<span className="muted" style={{ fontSize: 16 }}> / 100</span></div></div>
            <p className="muted" style={{ marginTop: 8 }}>Rule base {f.ruleBase ?? "–"} adjusted by asset criticality {f.criticality}/10. Exposure and threat intelligence are not in v1 because a pasted config does not carry them.</p>
          </section>
          <section className="card" aria-labelledby="fw"><h2 className="h2" id="fw">Maps to</h2>
            <div className="row" style={{ gap: 6 }}>{f.frameworks.map((x: string) => <span className="chip" key={x}>{x}</span>)}</div>
            <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>Indicative control IDs. Verify against your audit’s benchmark version.</p>
          </section>
          <section className="card"><dl className="kv" style={{ gridTemplateColumns: "100px 1fr" }}>
            <dt>First seen</dt><dd>{fmtDate(f.firstSeenAt)}</dd><dt>Last seen</dt><dd>{fmtDate(f.lastSeenAt)}</dd>{f.owner && <><dt>Owner</dt><dd>{f.owner}</dd></>}
          </dl></section>
        </aside>
      </div>
      {dlg && <StatusDialog kind={dlg} onClose={() => setDlg(null)} onSubmit={setStatus} />}
    </>
  );
}

function StatusDialog({ kind, onClose, onSubmit }: { kind: "accepted" | "false_positive"; onClose: () => void; onSubmit: (b: object) => Promise<void> }) {
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const min = new Date(Date.now() + 86400_000).toISOString().slice(0, 10);
  const max = new Date(Date.now() + 365 * 86400_000).toISOString().slice(0, 10);
  async function go(e: FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try { await onSubmit({ status: kind, reason, acceptedUntil: kind === "accepted" ? new Date(until + "T23:59:59Z").toISOString() : undefined }); }
    catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  }
  return (
    <Dialog title={kind === "accepted" ? "Accept this risk" : "Mark as false positive"} onClose={onClose}>
      <form onSubmit={go} style={{ display: "grid", gap: 16 }}>
        <label className="field">Reason<textarea className="textarea" style={{ fontFamily: "var(--font-sans)" }} rows={3} required minLength={5} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
        {kind === "accepted" && <label className="field">Review again on<input className="input" type="date" required min={min} max={max} value={until} onChange={(e) => setUntil(e.target.value)} /></label>}
        {err && <div className="err" role="alert">{err}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>Save</button></div>
      </form>
    </Dialog>
  );
}
