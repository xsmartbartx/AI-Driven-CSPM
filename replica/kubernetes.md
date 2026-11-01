# Checking Kubernetes workloads

Six rules for the settings that matter most in a Pod or anything that makes pods (Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob). Defaults follow Kubernetes: an unspecified `allowPrivilegeEscalation` is true, and a container without `runAsNonRoot` or a non-zero `runAsUser` may run as root; a pod's `securityContext` applies to containers that do not override it; init containers count.

| rule | severity driver |
| --- | --- |
| Privileged, dangerous capabilities (`ALL`, `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`), or `hostNetwork` / `hostPID` / `hostIPC` | highest |
| `hostPath` volume | high |
| May run as root | medium to high |
| Privilege escalation allowed | medium |
| Image not pinned (no tag, `:latest`) | low |
| No memory limit | low |

Every finding carries a **Kubernetes YAML fix** and the caveat that goes with it.

## In CI, before deploy
```bash
kubectl kustomize . | yq -o=json '.' > manifests.json     # or: kubectl get deploy,sts,ds,cronjob,job,pod -A -o json > manifests.json
CSPM_API_KEY=cspm_... node deploy/k8s-check.mjs manifests.json --show-fixes
```
Exit code **0** passed, **1** findings at or above `--fail-on` (default `high`), **2** the check could not run. A **read-only** key is enough. The script sends only the settings the rules read: no environment variables, commands, secret references, config maps or annotations. Nothing is stored and no scan is used. API: `POST /api/kubernetes/check` with `{ "manifests": …, "failOn": "high" }` (8 MB, 60 an hour per organization). Rule suppressions for everywhere or an environment (read from the namespace or an `environment` label) are honoured.

## As part of a scan
Resources of type `k8s_workload` can also be pasted into a normal scan, and then follow the same lifecycle as other findings (history, status, suppression, alerts). The converter produces them: `fromKubernetesManifests` in `lib/cspm-engine`.

## What it does not do
It does not read your cluster, RBAC, network policies, secrets, admission controls or the contents of images; it is a check of the manifests you give it. Compliance (CIS-K8s control IDs, indicative) appears only for organizations that have Kubernetes assets, so other organizations' coverage numbers are unchanged.
