import { useState, type FormEvent } from "react";
import { Link } from "wouter";
import { api, ApiError, useApi } from "../api";
import { useMe } from "../App";
import { Dialog, Empty, ErrorBox, fmtTime, Skeleton } from "../ui";

interface Conn { id: string; accountId: string; region: string; roleArn: string; status: "pending" | "connected" | "error"; lastSyncAt: string | null; lastError: string | null; verifiedAt: string | null; lastScanId: string | null; externalId?: string }
interface Setup { principalAccountId: string; externalId: string; roleArn: string; template: string }

const STATUS: Record<Conn["status"], { label: string; cls: string }> = { pending: { label: "Not verified", cls: "" }, connected: { label: "Connected", cls: "ok" }, error: { label: "Needs attention", cls: "critical" } };

function copy(text: string, ok: () => void, fail: () => void) { navigator.clipboard?.writeText(text).then(ok, fail); }

export function Cloud() {
  const { can, toast } = useMe();
  const { data, error, loading, reload } = useApi<any>("/cloud-accounts");
  const [connect, setConnect] = useState(false);
  const [setup, setSetup] = useState<Setup | null>(null);
  const [busy, setBusy] = useState<string>("");
  const [result, setResult] = useState<{ id: string; scanId: string; findingCount: number; notes: string[]; complete: boolean } | null>(null);

  async function act(c: Conn, kind: "verify" | "scan") {
    setBusy(`${kind}:${c.id}`); setResult(null);
    try {
      if (kind === "verify") { await api("POST", `/cloud-accounts/${c.id}/verify`); toast("Connected. The role works."); }
      else { const r = await api<any>("POST", `/cloud-accounts/${c.id}/scan`); setResult({ id: c.id, scanId: r.id, findingCount: r.findingCount, notes: r.notes ?? [], complete: r.complete }); }
    } catch (e) { toast((e as ApiError).message); }
    finally { setBusy(""); reload(); }
  }
  async function showSetup(c: Conn) {
    try { setSetup(await api<Setup>("GET", `/cloud-accounts/${c.id}/setup`)); } catch (e) { toast((e as ApiError).message); }
  }
  async function remove(c: Conn) {
    if (!confirm(`Disconnect AWS account ${c.accountId} (${c.region})? Its findings and assets stay.`)) return;
    try { await api("DELETE", `/cloud-accounts/${c.id}`); toast("Disconnected"); reload(); } catch (e) { toast((e as ApiError).message); }
  }

  const enabled = data?.connector.enabled;
  return (
    <>
      <div className="page-h">
        <div><h1>Cloud accounts</h1><p>Connect AWS with a read-only role. NEXORA keeps no AWS keys, only short-lived access while it scans.</p></div>
        {can("admin") && enabled && <button className="btn primary" onClick={() => setConnect(true)}>Connect AWS account</button>}
      </div>

      {error && <ErrorBox error={error} retry={reload} />}
      {loading && !data && <div className="card"><Skeleton lines={4} h={20} /></div>}
      {data && !enabled && (
        <div className="banner" role="status">AWS connections are not switched on for this NEXORA server yet, so you can only scan configurations you paste. Whoever runs the server enables it (see <code>replica/aws-setup.md</code>).</div>
      )}
      {result && (
        <div className="banner" role="status">
          <strong>Scan finished: {result.findingCount} finding{result.findingCount === 1 ? "" : "s"}.</strong> <Link href={`/scans/${result.scanId}`}>See the result</Link>
          {!result.complete && <> Some things could not be checked, so findings for resources that no longer appear were left as they were.</>}
          {result.notes.length > 0 && <ul style={{ margin: "8px 0 0", paddingLeft: 18 }}>{result.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>}
        </div>
      )}

      {data && enabled && data.items.length === 0 && (
        <Empty title="No AWS account connected" action={can("admin") ? <button className="btn primary lg" onClick={() => setConnect(true)}>Connect AWS account</button> : undefined}>
          You create a read-only role in your AWS account (we give you a template), then NEXORA reads your S3 buckets, security groups, IAM policies and RDS databases and keeps the findings up to date.
          {!can("admin") && " Ask an admin in your organization to connect one."}
        </Empty>
      )}

      {data && data.items.length > 0 && (
        <div className="grid">
          {(data.items as Conn[]).map((c) => (
            <section key={c.id} className="card" aria-label={`AWS account ${c.accountId} in ${c.region}`}>
              <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <h2 className="h2" style={{ marginBottom: 4 }}>AWS {c.accountId} <span className="muted" style={{ fontWeight: 400 }}>· {c.region}</span></h2>
                  <span className={`chip ${STATUS[c.status].cls}`}>{STATUS[c.status].label}</span>{" "}
                  <span className="muted">{c.lastSyncAt ? `Last scan ${fmtTime(c.lastSyncAt)}` : "Not scanned yet"}</span>
                </div>
                <div className="row">
                  {can("admin") && c.status !== "connected" && <button className="btn" onClick={() => showSetup(c)}>Setup instructions</button>}
                  {can("admin") && <button className="btn primary" onClick={() => act(c, "verify")} disabled={!!busy} aria-busy={busy === `verify:${c.id}`}>{busy === `verify:${c.id}` ? "Checking…" : c.status === "connected" ? "Check again" : "Verify connection"}</button>}
                  {can("analyst") && c.status === "connected" && <button className="btn primary" onClick={() => act(c, "scan")} disabled={!!busy} aria-busy={busy === `scan:${c.id}`}>{busy === `scan:${c.id}` ? "Scanning…" : "Scan now"}</button>}
                  {can("admin") && <button className="btn danger" onClick={() => remove(c)} disabled={!!busy}>Disconnect</button>}
                </div>
              </div>
              {c.lastError && <p className="err" role="alert" style={{ marginTop: 12 }}>{c.lastError}</p>}
              <p className="muted" style={{ marginTop: 8, overflowWrap: "anywhere" }}>Role: {c.roleArn}</p>
            </section>
          ))}
        </div>
      )}

      <section className="card" aria-labelledby="what">
        <h2 className="h2" id="what">What NEXORA reads</h2>
        <p className="muted">Only names, settings and policies; never your data. The role can list and describe these and nothing else:</p>
        <p style={{ marginTop: 8 }}>{(data?.readOnlyActions ?? []).map((a: string) => <code key={a} style={{ marginRight: 6, display: "inline-block" }}>{a}</code>)}</p>
        <p className="muted" style={{ marginTop: 8 }}>Checks cover S3 buckets, EC2 security groups, customer-managed IAM policies that are in use, and RDS databases in the region you choose. Add one connection per region.</p>
      </section>

      {connect && data && <ConnectDialog regions={data.regions} defaultRoleName={data.defaultRoleName} onClose={() => { setConnect(false); reload(); }} onCreated={(s) => { setConnect(false); setSetup(s); reload(); }} />}
      {setup && <SetupDialog s={setup} onClose={() => setSetup(null)} />}
    </>
  );
}

function ConnectDialog({ regions, defaultRoleName, onClose, onCreated }: { regions: string[]; defaultRoleName: string; onClose: () => void; onCreated: (s: Setup) => void }) {
  const [accountId, setAccountId] = useState("");
  const [region, setRegion] = useState("eu-west-1");
  const [roleName, setRoleName] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr(""); setBusy(true);
    try {
      const r = await api<any>("POST", "/cloud-accounts", { accountId: accountId.trim(), region, roleName: roleName.trim() || undefined });
      onCreated({ principalAccountId: r.principalAccountId, externalId: r.externalId, roleArn: r.roleArn, template: r.template });
    } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  }
  return (
    <Dialog title="Connect an AWS account" onClose={onClose}>
      <form onSubmit={submit} style={{ display: "grid", gap: 16 }}>
        <label className="field">AWS account id (12 digits)<input className="input" inputMode="numeric" pattern="\d{12}" required value={accountId} onChange={(e) => setAccountId(e.target.value)} placeholder="123456789012" autoComplete="off" /></label>
        <label className="field">Region to scan<select className="select" value={region} onChange={(e) => setRegion(e.target.value)}>{regions.map((r) => <option key={r} value={r}>{r}</option>)}</select></label>
        <label className="field">Role name <span className="muted" style={{ fontWeight: 400 }}>(optional, default {defaultRoleName})</span><input className="input" value={roleName} onChange={(e) => setRoleName(e.target.value)} placeholder={defaultRoleName} autoComplete="off" /></label>
        {err && <div className="err" role="alert">{err}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}><button type="button" className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>Continue</button></div>
      </form>
    </Dialog>
  );
}

function SetupDialog({ s, onClose }: { s: Setup; onClose: () => void }) {
  const { toast } = useMe();
  const download = () => {
    const url = URL.createObjectURL(new Blob([s.template], { type: "text/yaml" }));
    const a = document.createElement("a"); a.href = url; a.download = "nexora-cspm-role.yaml"; a.click(); URL.revokeObjectURL(url);
  };
  return (
    <Dialog title="Create the read-only role in AWS" onClose={onClose}>
      <ol style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 10 }}>
        <li>In the AWS console for that account, open <strong>CloudFormation → Create stack → With new resources</strong>, choose <em>Upload a template file</em>, and upload the file below (or paste it).</li>
        <li>Create the stack and tick the box that it creates an IAM role. It creates one role, <code>{s.roleArn.split("/").pop()}</code>, that trusts only AWS account <code>{s.principalAccountId}</code> with your External ID.</li>
        <li>Come back here and press <strong>Verify connection</strong>.</li>
      </ol>
      <dl className="kv" style={{ gridTemplateColumns: "140px 1fr" }}>
        <dt>NEXORA account</dt><dd><code>{s.principalAccountId}</code></dd>
        <dt>External ID</dt><dd><code>{s.externalId}</code></dd>
        <dt>Role ARN</dt><dd style={{ overflowWrap: "anywhere" }}><code>{s.roleArn}</code></dd>
      </dl>
      <pre className="code" tabIndex={0} aria-label="CloudFormation template" style={{ maxHeight: 220 }}>{s.template}</pre>
      <p className="muted" style={{ fontSize: 13 }}>The role can only list and describe S3 buckets, security groups, IAM policies and RDS instances. Read the template before you deploy it.</p>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button className="btn" onClick={() => copy(s.template, () => toast("Template copied"), () => toast("Select the template and copy it"))}>Copy template</button>
        <button className="btn" onClick={download}>Download template</button>
        <button className="btn primary" onClick={onClose}>Done</button>
      </div>
    </Dialog>
  );
}
