import { evaluate, fixFor, postureScore, type Resource, type Severity } from "@workspace/cspm-engine";
import type { Queryable } from "@workspace/db";
import { activeSuppressions } from "./suppressions";

const RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

/**
 * The shared tail of the "check before you deploy" endpoints (Terraform plans, Kubernetes manifests): run the rules,
 * drop what the organization suppressed everywhere or for an environment, and say whether the change should fail.
 * Nothing is stored. Suppressions for one asset do not apply: a plan address is not an account asset.
 */
export async function checkResources(q: Queryable, orgId: string, resources: Resource[], failOn: Severity) {
  const sup = (await activeSuppressions(q, orgId)).filter((s) => !s.assetId);
  const env = new Map(resources.map((x) => [x.name, x.environment as string | undefined]));
  const { findings } = evaluate(resources);
  let suppressed = 0;
  const kept = findings.filter((f) => {
    const e = env.get(f.resourceName);
    const hit = sup.find((s) => s.ruleId === f.ruleId && (!s.environment || s.environment === e));
    if (hit) suppressed++;
    return !hit;
  });
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>;
  kept.forEach((f) => counts[f.severity]++);
  return {
    resourceCount: resources.length, counts, score: postureScore(counts), suppressed, failOn, fail: kept.some((f) => RANK[f.severity] >= RANK[failOn]),
    findings: kept.map((f) => ({ ruleId: f.ruleId, title: f.title, severity: f.severity, riskScore: f.riskScore, address: f.resourceName, resourceType: f.resourceType, evidence: f.evidence, remediation: f.remediation, fix: fixFor(f.ruleId, f) })),
  };
}
