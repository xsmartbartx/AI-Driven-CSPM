import { Link } from "wouter";
import { useApi } from "../api";
import { useMe } from "../App";
import { Empty, ErrorBox, Sev, Skeleton } from "../ui";

interface Node { id: string; kind: "internet" | "instance" | "role" | "database" | "bucket" | "account"; name: string; environment?: string }
interface Edge { from: string; to: string; kind: string; label: string; fix: { id: string; action: string; asset: string } }
interface Path { id: string; score: number; severity: string; title: string; target: string; nodes: Node[]; edges: Edge[]; findings: { id: string; title: string; severity: string; assetName: string }[] }
interface Choke { fixId: string; action: string; asset: string; paths: number }

const KIND: Record<Node["kind"], string> = { internet: "Internet", instance: "Server", role: "Role", database: "Database", bucket: "Bucket", account: "AWS account" };

function Chain({ p }: { p: Path }) {
  return (
    <ol className="chain" aria-label="Steps of this attack path">
      {p.nodes.map((n, i) => (
        <li key={n.id} className={`hop ${n.kind}`}>
          <span className="hop-kind">{KIND[n.kind]}</span>
          <span className="hop-name">{n.name}</span>
          {n.environment && <span className="muted" style={{ fontSize: 12 }}>{n.environment}</span>}
          {i < p.nodes.length - 1 && <span className="hop-arrow" aria-hidden="true">→</span>}
        </li>
      ))}
    </ol>
  );
}

export function AttackPaths() {
  const { can } = useMe();
  const { data, error, loading, reload } = useApi<{ paths: Path[]; chokePoints: Choke[]; coverage: { instances: number; roles: number; instancesWithoutRole: number; hasRelationshipData: boolean }; notes: string[]; assetCount: number }>("/attack-paths");
  const critical = data?.paths.filter((p) => p.severity === "critical").length ?? 0;
  const best = data?.chokePoints[0];

  return (
    <>
      <div className="page-h"><div><h1>Attack paths</h1><p>How an attacker could get from the internet to your account or your data, one step at a time, using the configuration NEXORA scanned.</p></div></div>
      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="card"><Skeleton lines={5} h={20} /></div>}

      {data && data.paths.length === 0 && (
        <Empty title={data.coverage.hasRelationshipData ? "No attack paths found" : "Nothing to build paths from yet"}
          action={can("analyst") && !data.coverage.hasRelationshipData ? <div className="row"><Link href="/integrations" className="btn primary lg">Connect an AWS account</Link><Link href="/scans/new?sample=paths" className="btn lg">Try a sample with paths</Link></div> : undefined}>
          {data.coverage.hasRelationshipData
            ? "None of your internet-facing servers can reach the account's control or your data through the relationships NEXORA can see. That is good news, within the limits listed below."
            : "A path needs servers and the roles they run as, which a pasted list of buckets and policies does not include. Connect an AWS account (with the latest setup template), or add servers and roles to a pasted configuration."}
        </Empty>
      )}

      {data && data.paths.length > 0 && (
        <>
          <section className="grid g3" aria-label="Summary">
            <div className="card kpi"><div className="label">Attack paths</div><div className="value">{data.paths.length}</div><div className="sub">{critical} critical</div></div>
            <div className="card kpi"><div className="label">Best single fix</div><div className="value">{best?.paths ?? 0}<span className="muted" style={{ fontSize: 16 }}> path{best?.paths === 1 ? "" : "s"}</span></div><div className="sub">{best ? `broken by changing ${best.asset}` : ""}</div></div>
            <div className="card kpi"><div className="label">Servers checked</div><div className="value">{data.coverage.instances}</div><div className="sub">{data.coverage.roles} role{data.coverage.roles === 1 ? "" : "s"} read{data.coverage.instancesWithoutRole ? ` · ${data.coverage.instancesWithoutRole} without role data` : ""}</div></div>
          </section>

          {data.chokePoints.length > 0 && (
            <section className="card" aria-labelledby="fix-first">
              <h2 className="h2" id="fix-first">Fix these first</h2>
              <p className="muted" style={{ marginBottom: 8 }}>Each change below cuts the number of paths shown. Start at the top.</p>
              <ol className="list" style={{ margin: 0, paddingLeft: 20 }}>
                {data.chokePoints.map((c) => (
                  <li key={c.fixId} style={{ padding: "10px 0" }}><span className="title">{c.action}</span> <span className="chip">{c.paths} path{c.paths === 1 ? "" : "s"}</span></li>
                ))}
              </ol>
            </section>
          )}

          <div className="grid">
            {data.paths.map((p) => (
              <article key={p.id} className="card" aria-label={p.title}>
                <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start", flexWrap: "nowrap" }}>
                  <h2 className="h2" style={{ margin: 0 }}>{p.title}</h2>
                  <span className="row" style={{ flexWrap: "nowrap", flex: "none" }}><Sev s={p.severity} /><strong aria-label={`Path risk ${p.score} of 100`}>{p.score}</strong></span>
                </div>
                <Chain p={p} />
                <h3 className="h2" style={{ fontSize: 14, margin: "12px 0 4px" }}>Why each step works</h3>
                <ol style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 4 }}>{p.edges.map((e, i) => <li key={i}>{e.label}</li>)}</ol>
                <h3 className="h2" style={{ fontSize: 14, margin: "12px 0 4px" }}>How to break it (any one is enough)</h3>
                <ul style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 4 }}>{[...new Map(p.edges.map((e) => [e.fix.id, e.fix.action])).values()].map((a) => <li key={a}>{a}</li>)}</ul>
                {p.findings.length > 0 && (
                  <>
                    <h3 className="h2" style={{ fontSize: 14, margin: "12px 0 4px" }}>Related findings</h3>
                    <div className="row" style={{ gap: 8 }}>{p.findings.map((f) => <Link key={f.id} href={`/findings/${f.id}`} className="chip" style={{ textDecoration: "none" }} title={f.assetName}>{f.title}</Link>)}</div>
                  </>
                )}
              </article>
            ))}
          </div>
        </>
      )}

      {data && (
        <details className="card">
          <summary style={{ cursor: "pointer", fontWeight: 600 }}>What this can and cannot see</summary>
          <ul style={{ margin: "12px 0 0", paddingLeft: 20, display: "grid", gap: 6 }}>{data.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
          <p className="muted" style={{ marginTop: 8 }}>A path shows that the configuration allows each step. It does not prove an attacker can succeed, and it does not replace a penetration test.</p>
        </details>
      )}
    </>
  );
}
