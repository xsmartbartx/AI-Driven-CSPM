import { useState } from "react";
import { Link } from "wouter";
import { useApi } from "../api";
import { useMe } from "../App";
import { Empty, ErrorBox, Kpi, ScoreRing, Sev, Skeleton, Trend } from "../ui";

const RANGES = [["30d", "30 days"], ["3m", "3 months"], ["6m", "6 months"]] as const;
const TYPE_LABEL: Record<string, string> = { s3_bucket: "Storage buckets", security_group: "Security groups", iam_policy: "IAM policies", database: "Databases" };

export function Overview() {
  const { can } = useMe();
  const [range, setRange] = useState<string>("30d");
  const { data, error, loading, reload } = useApi<any>(`/overview?range=${range}`);

  return (
    <>
      <div className="page-h">
        <div><h1>Overview</h1><p>Your cloud security posture at a glance.</p></div>
        <div className="row">
          <div className="seg" role="group" aria-label="Time range">
            {RANGES.map(([k, l]) => <button key={k} aria-pressed={range === k} onClick={() => setRange(k)}>{l}</button>)}
          </div>
          {can("analyst") && <Link href="/scans/new" className="btn primary">New scan</Link>}
        </div>
      </div>

      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="grid g4">{[0, 1, 2, 3].map((i) => <div key={i} className="card"><Skeleton lines={3} /></div>)}</div>}

      {data && !data.hasData && (
        <Empty title="Run your first scan"
          action={can("analyst") ? <div className="row"><Link href="/scans/new?sample=1" className="btn primary lg">Try with a sample config</Link><Link href="/scans/new" className="btn lg">Paste your own</Link></div> : undefined}>
          Describe your buckets, security groups, IAM policies and databases as JSON. You get ranked findings with a fix for each in seconds.
          {!can("analyst") && " Ask an analyst or admin in your organization to run the first scan."}
        </Empty>
      )}

      {data?.hasData && (
        <>
          {data.usage.scans.used >= data.usage.scans.limit * 0.8 && (
            <div className="banner" role="status">
              You have used {data.usage.scans.used} of {data.usage.scans.limit} scans this month. <Link href="/usage">See plans</Link>
            </div>
          )}
          <section className="grid g4" aria-label="Key numbers">
            <div className="card row" style={{ flexWrap: "nowrap" }}>
              <ScoreRing score={data.score} />
              <div className="kpi">
                <div className="label">Posture score</div>
                <div className={`sub ${data.delta == null ? "" : data.delta >= 0 ? "up" : "down"}`}>
                  {data.delta == null ? "Rescan to see change" : `${data.delta >= 0 ? "▲" : "▼"} ${Math.abs(data.delta)} in this period`}
                </div>
              </div>
            </div>
            <Kpi label="Critical findings" value={data.counts.critical} sub={`${data.counts.high} high · ${data.counts.medium} medium · ${data.counts.low} low`} />
            <Kpi label="Assets scanned" value={data.assets.total} sub={data.assets.byProvider.map((p: any) => `${p.provider.toUpperCase()} ${p.n}`).join(" · ")} />
            <Kpi label="Mapped controls passing" value={`${data.compliance.passing} of ${data.compliance.total}`} sub={<Link href="/compliance">View frameworks</Link>} />
          </section>

          <div className="grid g21">
            <section className="card" aria-labelledby="t-h">
              <h2 className="h2" id="t-h">Posture over time</h2>
              <Trend points={data.trend} />
            </section>
            <section className="card" aria-labelledby="s-h">
              <h2 className="h2" id="s-h">Open findings by severity</h2>
              <div style={{ display: "grid", gap: 14 }}>
                {(["critical", "high", "medium", "low"] as const).map((s) => (
                  <div key={s}>
                    <div className="row" style={{ justifyContent: "space-between", marginBottom: 4 }}>
                      <Link href={`/findings?severity=${s}`}><Sev s={s} /></Link><strong>{data.counts[s]}</strong>
                    </div>
                    <div className="bar" aria-hidden="true"><i style={{ width: `${data.openTotal ? (data.counts[s] / data.openTotal) * 100 : 0}%`, background: `var(--sev-${s})` }} /></div>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <div className="grid g21">
            <section className="card" aria-labelledby="a-h">
              <div className="row" style={{ justifyContent: "space-between" }}><h2 className="h2" id="a-h">Top actions</h2><Link href="/findings">All findings</Link></div>
              {data.topActions.length === 0 ? <p className="muted">No open findings. Nicely done.</p> : (
                <div className="list">
                  {data.topActions.map((f: any) => (
                    <Link key={f.id} href={`/findings/${f.id}`} className="rowlink">
                      <Sev s={f.severity} />
                      <div style={{ flex: 1, minWidth: 0 }}><div className="title">{f.title}</div><div className="muted" style={{ overflowWrap: "anywhere" }}>{f.assetName}</div></div>
                      <strong aria-label={`Risk ${f.riskScore}`}>{f.riskScore}</strong>
                    </Link>
                  ))}
                </div>
              )}
            </section>
            <section className="card" aria-labelledby="w-h">
              <h2 className="h2" id="w-h">Workloads</h2>
              <div className="list">
                {data.assets.byType.map((t: any) => (
                  <Link key={t.type} href={`/assets?type=${t.type}`} className="rowlink"><span style={{ flex: 1 }}>{TYPE_LABEL[t.type] ?? t.type}</span><strong>{t.n}</strong></Link>
                ))}
              </div>
            </section>
          </div>

          <section className="card" aria-labelledby="c-h">
            <h2 className="h2" id="c-h">Compliance frameworks</h2>
            <div className="grid g3">
              {data.compliance.frameworks.map((f: any) => (
                <div key={f.framework}>
                  <div className="row" style={{ justifyContent: "space-between" }}><strong>{f.framework}</strong><span>{f.coverage}%</span></div>
                  <div className="bar" style={{ marginTop: 6 }}><i style={{ width: `${f.coverage}%`, background: f.coverage >= 90 ? "var(--success)" : f.coverage >= 70 ? "var(--warning)" : "var(--danger)" }} /></div>
                  <div className="muted" style={{ marginTop: 4 }}>{f.failed} of {f.controls} mapped controls failing</div>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </>
  );
}
