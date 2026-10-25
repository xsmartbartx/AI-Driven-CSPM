# Using the NEXORA CSPM API with an API key

Create a key in **Settings → API keys** (admins and owners). It is shown once; only a hash is stored.

| option | values | default |
| --- | --- | --- |
| access | `read` (findings, assets, scans, attack paths) or `scan` (also run scans) | `scan` |
| expiresInDays | 1 to 365, or `null` for no expiry | `null` via the API; the Settings form defaults to 90 |

An expired or revoked key gets `401` on its next request. Keys never manage the team, billing, other keys or cloud accounts.

```bash
curl -H "Authorization: Bearer cspm_…" https://api.cspm.onenexora.com/api/findings
curl -H "Authorization: Bearer cspm_…" https://api.cspm.onenexora.com/api/attack-paths
curl -X POST -H "Authorization: Bearer cspm_…" -H "content-type: application/json" -d @config.json https://api.cspm.onenexora.com/api/scans   # scan keys only
```

Use a `read` key with an expiry for dashboards and reports, and a separate `scan` key for CI. Rotate by creating the new key, switching your tool over, then revoking the old one. Created keys and revocations appear in the audit log.
