import { Link } from "wouter";
import { Empty } from "../ui";

const COPY: Record<string, { title: string; body: string }> = {
  "attack-paths": { title: "Attack paths", body: "Chains such as internet → public server → over-privileged role → production database, shown as one risk instead of many alerts. This needs live cloud connections to know how resources relate, so it follows account connection." },
  ai: { title: "AI Security Center", body: "A daily brief and questions answered from your own findings. For now, open any finding and choose “Explain this finding”." },
  remediation: { title: "Remediation", body: "Generated Terraform fixes and pull requests for review. For now, every finding shows the manual fix." },
};

export function Planned({ name }: { name: string }) {
  const c = COPY[name];
  if (!c) return <Empty title="Page not found" action={<Link href="/" className="btn primary">Back to overview</Link>} />;
  return (
    <>
      <div className="page-h"><div><h1>{c.title}</h1><p>Not available yet</p></div></div>
      <Empty title="Planned, not built" action={<Link href="/" className="btn">Back to overview</Link>}>{c.body}</Empty>
    </>
  );
}
