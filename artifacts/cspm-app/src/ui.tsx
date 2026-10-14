import { useEffect, useId, useRef, type ReactNode } from "react";
import { ApiError } from "./api";

export const SEV_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
export const STATUS_LABEL: Record<string, string> = { open: "Open", fixed: "Fixed", accepted: "Accepted risk", false_positive: "False positive" };

export const Sev = ({ s }: { s: string }) => <span className={`chip ${s}`}>{SEV_LABEL[s] ?? s}</span>;
export const Status = ({ s }: { s: string }) => <span className={`chip ${s === "fixed" ? "ok" : ""}`}>{STATUS_LABEL[s] ?? s}</span>;

export function Icon({ d, size = 18 }: { d: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}
export const ICONS = {
  home: "M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10",
  alert: "M12 3l10 18H2zM12 10v5M12 18h.01",
  box: "M21 8l-9-5-9 5v8l9 5 9-5zM3 8l9 5 9-5M12 13v8",
  check: "M9 12l2 2 4-4M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  scan: "M4 8V5a1 1 0 011-1h3M16 4h3a1 1 0 011 1v3M20 16v3a1 1 0 01-1 1h-3M8 20H5a1 1 0 01-1-1v-3M7 12h10",
  history: "M3 12a9 9 0 109-9 9 9 0 00-7 3.5L3 8M3 3v5h5M12 7v5l3 2",
  users: "M16 11a4 4 0 10-8 0M4 21a8 8 0 0116 0",
  log: "M6 3h9l4 4v14H6zM14 3v5h5M9 13h7M9 17h7",
  cog: "M12 15a3 3 0 100-6 3 3 0 000 6zM19 12l2-1-2-4-2 1a7 7 0 00-2-1l-.5-2h-5L9 7a7 7 0 00-2 1L5 7l-2 4 2 1a7 7 0 000 2l-2 1 2 4 2-1a7 7 0 002 1l.5 2h5l.5-2a7 7 0 002-1l2 1 2-4-2-1a7 7 0 000-2z",
  card: "M3 6h18v12H3zM3 10h18",
  path: "M5 5a2 2 0 100 .01M19 19a2 2 0 100 .01M5 7v4a4 4 0 004 4h6a4 4 0 014 4",
  spark: "M12 3l2 5 5 2-5 2-2 5-2-5-5-2 5-2zM19 15l1 2 2 1-2 1-1 2-1-2-2-1 2-1z",
  wrench: "M14 6a4 4 0 005 5l-9 9a2 2 0 01-3-3l9-9a4 4 0 00-2-2z",
  file: "M6 3h9l4 4v14H6zM14 3v5h5",
  plug: "M9 2v6M15 2v6M6 8h12v4a6 6 0 01-12 0zM12 18v4",
  menu: "M4 6h16M4 12h16M4 18h16",
};

export function Skeleton({ lines = 3, h = 16 }: { lines?: number; h?: number }) {
  return (
    <div role="status" aria-busy="true" aria-label="Loading" style={{ display: "grid", gap: 10 }}>
      {Array.from({ length: lines }, (_, i) => <div key={i} className="skel" style={{ height: h, width: `${100 - i * 12}%` }} />)}
    </div>
  );
}

export function ErrorBox({ error, retry }: { error: ApiError | Error; retry?: () => void }) {
  return (
    <div className="banner error" role="alert">
      <div>{error.message}</div>
      {retry && <button className="btn sm" style={{ marginTop: 8 }} onClick={retry}>Try again</button>}
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty card">
      <h2>{title}</h2>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function ScoreRing({ score, size = 104 }: { score: number; size?: number }) {
  const r = size / 2 - 8, c = 2 * Math.PI * r;
  const color = score >= 80 ? "var(--success)" : score >= 50 ? "var(--warning)" : "var(--danger)";
  return (
    <div className="ring" style={{ width: size, height: size }} role="img" aria-label={`Posture score ${score} of 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-2)" strokeWidth="8" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={`${(c * score) / 100} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} style={{ transition: "stroke-dasharray .6s var(--ease)" }} />
      </svg>
      <b aria-hidden="true">{score}</b>
    </div>
  );
}

export function Trend({ points }: { points: { day: string; score: number }[] }) {
  const W = 640, H = 180, P = 28;
  if (points.length === 0) return <p className="muted">The trend appears after your first scan.</p>;
  const xs = (i: number) => (points.length === 1 ? W / 2 : P + (i * (W - 2 * P)) / (points.length - 1));
  const ys = (v: number) => H - P - (v / 100) * (H - 2 * P);
  const path = points.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(p.score).toFixed(1)}`).join(" ");
  return (
    <figure style={{ margin: 0 }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={`Posture score trend, latest ${points[points.length - 1]!.score}`}>
        {[0, 50, 100].map((g) => (
          <g key={g}>
            <line x1={P} x2={W - P} y1={ys(g)} y2={ys(g)} stroke="var(--border)" />
            <text x={4} y={ys(g) + 4} fontSize="11" fill="var(--text-muted)">{g}</text>
          </g>
        ))}
        {points.length > 1 && <path d={`${path} L${xs(points.length - 1)},${ys(0)} L${xs(0)},${ys(0)}Z`} fill="var(--accent)" opacity=".1" />}
        <path d={path} fill="none" stroke="var(--accent)" strokeWidth="2.5" strokeLinejoin="round" />
        {points.map((p, i) => <circle key={p.day} cx={xs(i)} cy={ys(p.score)} r="3.5" fill="var(--accent)"><title>{`${p.day}: ${p.score}`}</title></circle>)}
        <text x={P} y={H - 6} fontSize="11" fill="var(--text-muted)">{points[0]!.day}</text>
        <text x={W - P} y={H - 6} fontSize="11" fill="var(--text-muted)" textAnchor="end">{points[points.length - 1]!.day}</text>
      </svg>
      <table className="sr-only"><caption>Posture score by day</caption><tbody>{points.map((p) => <tr key={p.day}><td>{p.day}</td><td>{p.score}</td></tr>)}</tbody></table>
    </figure>
  );
}

export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "up" | "down" }) {
  return (
    <div className="card kpi">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {sub && <div className={`sub ${tone ?? ""}`}>{sub}</div>}
    </div>
  );
}

export function Dialog({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("input,select,textarea,button");
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab" && ref.current) {
        const f = [...ref.current.querySelectorAll<HTMLElement>("input,select,textarea,button:not([disabled]),a[href]")];
        if (!f.length) return;
        const a = f[0]!, z = f[f.length - 1]!;
        if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
        else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); prev?.focus(); };
  }, [onClose]);
  return (
    <div className="dlg-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dlg" role="dialog" aria-modal="true" aria-labelledby={id} ref={ref}>
        <h2 id={id} className="h2" style={{ margin: 0 }}>{title}</h2>
        {children}
      </div>
    </div>
  );
}

export const fmtDate = (s: string | Date) => new Date(s).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
export const fmtTime = (s: string | Date) => new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
