import type { Resource, Rule } from "./index";
import { LIMITS } from "./index";

/**
 * Kubernetes workload checks. A workload is a Pod, or anything that makes pods (Deployment, StatefulSet, DaemonSet,
 * ReplicaSet, Job, CronJob). The converter reads manifests as JSON (kubectl get -o json, or a YAML file converted with
 * `yq -o=json`) and keeps only the settings the rules look at. Defaults follow Kubernetes: a missing
 * allowPrivilegeEscalation is true, a container with no runAsNonRoot or non-zero runAsUser may run as root.
 */
interface Box { name: string; image: string; privileged: boolean; escalation: boolean; root: boolean; noMemoryLimit: boolean; latest: boolean; addedCaps: string[] }
const boxes = (r: Resource): Box[] => (Array.isArray(r["containers"]) ? (r["containers"] as Box[]) : []);
const names = (list: Box[]) => list.map((c) => c.name);
const DANGEROUS_CAPS = ["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"];

export const K8S_RULES: Rule[] = [
  {
    id: "k8s-privileged", title: "Workload runs privileged or shares the host's namespaces", resourceType: "k8s_workload", base: 92,
    remediation: "Remove privileged: true, hostNetwork, hostPID and hostIPC, and drop dangerous capabilities. If a component truly needs host access, isolate it in its own namespace with strict admission rules.",
    frameworks: ["CIS-K8s 5.2.2", "NIST-800-53 AC-6", "NIST-800-53 CM-7"],
    check: (r) => {
      const priv = boxes(r).filter((c) => c.privileged || c.addedCaps.some((x) => DANGEROUS_CAPS.includes(x)));
      const host = ["hostNetwork", "hostPID", "hostIPC"].filter((k) => r[k] === true);
      return priv.length || host.length ? { containers: names(priv), host_namespaces: host } : null;
    },
  },
  {
    id: "k8s-host-path", title: "Workload mounts a path from the host", resourceType: "k8s_workload", base: 78,
    remediation: "Use emptyDir, a PersistentVolumeClaim or a ConfigMap/Secret volume instead of hostPath. If a hostPath is unavoidable, make it read-only and as narrow as possible.",
    frameworks: ["CIS-K8s 5.2.12", "NIST-800-53 AC-6"],
    check: (r) => (Array.isArray(r["hostPaths"]) && (r["hostPaths"] as string[]).length ? { host_paths: r["hostPaths"] } : null),
  },
  {
    id: "k8s-run-as-root", title: "Container may run as root", resourceType: "k8s_workload", base: 62,
    remediation: "Set securityContext.runAsNonRoot: true and a non-zero runAsUser, and build the image to run as an unprivileged user.",
    frameworks: ["CIS-K8s 5.2.6", "NIST-800-53 AC-6", "ISO-27001 A.8.2"],
    check: (r) => { const c = boxes(r).filter((x) => x.root); return c.length ? { containers: names(c) } : null; },
  },
  {
    id: "k8s-privilege-escalation", title: "Container can gain more privileges than its parent process", resourceType: "k8s_workload", base: 48,
    remediation: "Set securityContext.allowPrivilegeEscalation: false on every container, and drop all capabilities you do not need.",
    frameworks: ["CIS-K8s 5.2.5", "NIST-800-53 AC-6"],
    check: (r) => { const c = boxes(r).filter((x) => x.escalation); return c.length ? { containers: names(c) } : null; },
  },
  {
    id: "k8s-latest-image", title: "Container image is not pinned to a version", resourceType: "k8s_workload", base: 34,
    remediation: "Pin images to a specific version tag, or better to a digest (image@sha256:…), so a deployment is reproducible and a changed upstream image cannot slip in.",
    frameworks: ["NIST-800-53 CM-2", "ISO-27001 A.8.9"],
    check: (r) => { const c = boxes(r).filter((x) => x.latest); return c.length ? { images: c.map((x) => x.image) } : null; },
  },
  {
    id: "k8s-no-limits", title: "Container has no memory limit", resourceType: "k8s_workload", base: 26,
    remediation: "Set resources.limits.memory (and cpu) so one container cannot starve the node or its neighbours.",
    frameworks: ["NIST-800-53 SC-5", "ISO-27001 A.8.6"],
    check: (r) => { const c = boxes(r).filter((x) => x.noMemoryLimit); return c.length ? { containers: names(c) } : null; },
  },
];

export interface KubernetesResult { resources: Resource[]; skipped: { type: string; count: number }[]; notes: string[]; errors: string[] }
type Json = Record<string, any>;
const obj = (v: unknown): Json | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : null);
const arr = (v: unknown): any[] => (Array.isArray(v) ? v : []);
const POD_KINDS = new Set(["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob"]);

const podSpecOf = (m: Json): Json | null =>
  m["kind"] === "Pod" ? obj(m["spec"]) : m["kind"] === "CronJob" ? obj(m["spec"]?.["jobTemplate"]?.["spec"]?.["template"]?.["spec"]) : obj(m["spec"]?.["template"]?.["spec"]);

const envOf = (labels: unknown, ns: string): Resource["environment"] => {
  const t = obj(labels); const v = String(t?.["environment"] ?? t?.["env"] ?? t?.["Environment"] ?? ns).toLowerCase();
  return /prod/.test(v) ? "production" : /(stag|stg|qa|test)/.test(v) ? "staging" : /dev/.test(v) ? "development" : undefined;
};

export function fromKubernetesManifests(input: unknown): KubernetesResult {
  const fail = (e: string): KubernetesResult => ({ resources: [], skipped: [], notes: [], errors: [e] });
  const root = obj(input);
  const docs: Json[] = Array.isArray(input) ? input.map(obj).filter((x): x is Json => !!x) : root && Array.isArray(root["items"]) ? arr(root["items"]).map(obj).filter((x): x is Json => !!x) : root ? [root] : [];
  if (!docs.length || !docs.some((d) => typeof d["kind"] === "string"))
    return fail("This does not look like Kubernetes manifests in JSON. Use: kubectl get deploy,sts,ds,cronjob,job,pod -A -o json, or convert a YAML file with: yq -o=json '.' manifest.yaml");
  const skipped = new Map<string, number>(); const resources: Resource[] = []; const seen = new Set<string>();
  for (const m of docs) {
    const kind = String(m["kind"]);
    if (!POD_KINDS.has(kind)) { skipped.set(kind, (skipped.get(kind) ?? 0) + 1); continue; }
    const spec = podSpecOf(m); if (!spec) continue;
    const meta = obj(m["metadata"]) ?? {}; const ns = String(meta["namespace"] ?? "default"); const name = `${kind}/${ns}/${String(meta["name"] ?? meta["generateName"] ?? "unnamed")}`;
    if (seen.has(name)) continue; seen.add(name);
    const podSc = obj(spec["securityContext"]) ?? {};
    const containers: Box[] = [...arr(spec["containers"]), ...arr(spec["initContainers"])].map(obj).filter((x): x is Json => !!x).map((c) => {
      const sc = obj(c["securityContext"]) ?? {};
      const nonRoot = (sc["runAsNonRoot"] ?? podSc["runAsNonRoot"]) === true;
      const user = sc["runAsUser"] ?? podSc["runAsUser"];
      const image = String(c["image"] ?? "");
      const tag = image.includes("@sha256:") ? "digest" : image.slice(image.lastIndexOf("/") + 1).includes(":") ? image.slice(image.lastIndexOf(":") + 1) : "";
      return {
        name: String(c["name"] ?? "container"), image,
        privileged: sc["privileged"] === true, escalation: sc["allowPrivilegeEscalation"] !== false,
        root: !(nonRoot || (typeof user === "number" && user > 0)),
        noMemoryLimit: !obj(c["resources"])?.["limits"]?.["memory"],
        latest: tag === "" || tag === "latest",
        addedCaps: arr(sc["capabilities"]?.["add"]).map(String),
      };
    });
    const r: Resource = {
      type: "k8s_workload", name, kind, namespace: ns, containers,
      hostNetwork: spec["hostNetwork"] === true, hostPID: spec["hostPID"] === true, hostIPC: spec["hostIPC"] === true,
      hostPaths: arr(spec["volumes"]).map(obj).filter((v): v is Json => !!v && !!obj(v["hostPath"])).map((v) => String(v["hostPath"].path ?? v["name"] ?? "?")),
    };
    const env = envOf(meta["labels"], ns); if (env) r["environment"] = env;
    resources.push(r);
  }
  const notes = ["Checked: Pods and the workloads that create them. Policies, RBAC, network policies, secrets and admission controls are not read."];
  if (resources.length > LIMITS.maxResources) return fail(`Too many workloads (${resources.length}). The limit is ${LIMITS.maxResources} per check.`);
  return { resources, skipped: [...skipped].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count), notes, errors: [] };
}
