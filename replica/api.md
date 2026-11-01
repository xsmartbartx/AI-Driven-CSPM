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

## The full description (OpenAPI)

`GET /api/openapi.json` (no key needed) is an OpenAPI 3.1 description of everything a key can do: operations, parameters, request bodies, the main response shapes, the role each needs (`x-min-role`: `viewer` for read-only keys, `analyst` for scan keys) and the error format. Import it into Postman, Insomnia or a code generator, for example `npx openapi-typescript https://api.cspm.onenexora.com/api/openapi.json -o cspm.d.ts`.

Routes for people (sign-in, team, billing, API-key and cloud-account management, notification and suppression settings) are not part of the key API. The document is kept honest by a test that calls every listed operation with a read-only key, a scan key and no key, and fails if a route exists that is neither listed nor on the people-only list. Large or still-changing responses (the overview, attack paths, compliance) are described by their main fields and allow extra ones.
