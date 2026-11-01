import { RULES } from "@workspace/cspm-engine";

/**
 * The public API: everything a Bearer API key can do (read-only keys are viewers, scan keys are analysts).
 * Routes for people (sign-in, team, billing, settings) are deliberately not listed. test/api-openapi.test.ts checks that
 * every operation here exists with the stated minimum role, and that no other route sneaks in unlisted.
 */
type Json = Record<string, unknown>;
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const json = (schema: Json, description = "OK") => ({ description, content: { "application/json": { schema } } });
const err = (description: string) => ({ description, content: { "application/json": { schema: ref("Error") } } });
const SEV = { type: "string", enum: ["critical", "high", "medium", "low"] };
const idParam = { name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } };

/** One operation. `role` is the minimum role (shown as x-min-role); a read-only key is a viewer. */
const op = (role: "viewer" | "analyst", summary: string, o: Json): Json => ({
  summary, security: [{ apiKey: [] }], "x-min-role": role,
  ...o,
  responses: { ...(o["responses"] as Json), "401": err("Missing, wrong or expired API key"), ...(role === "analyst" ? { "403": err("This key is read-only") } : {}), "429": err("Too many requests") },
});

export function buildOpenApi(serverUrl: string): Json {
  return {
    openapi: "3.1.0",
    info: {
      title: "NEXORA CSPM API", version: "1.0.0",
      description: "Read findings, assets and attack paths, run scans, and check Terraform plans before apply. Authenticate with `Authorization: Bearer cspm_…` (Settings → API keys). A read-only key can use every operation marked `viewer`; a scan key can also use `analyst` operations. Errors are `{ \"error\": { \"code\", \"message\" } }`.",
    },
    servers: [{ url: serverUrl }],
    security: [{ apiKey: [] }],
    paths: {
      "/healthz": { get: { summary: "Is the API up", security: [], responses: { "200": json({ type: "object", properties: { status: { const: "ok" } } }) } } },
      "/overview": { get: op("viewer", "Posture score, counts, trend and top actions", { parameters: [{ name: "range", in: "query", schema: { enum: ["30d", "3m", "6m"], default: "30d" } }], responses: { "200": json(ref("Overview")) } }) },
      "/findings": { get: op("viewer", "List findings", {
        parameters: [
          { name: "status", in: "query", schema: { enum: ["open", "fixed", "accepted", "false_positive", "all"], default: "open" } },
          { name: "severity", in: "query", schema: SEV }, { name: "type", in: "query", schema: { type: "string" }, description: "Asset type, e.g. s3_bucket" },
          { name: "q", in: "query", schema: { type: "string", maxLength: 100 }, description: "Searches title and asset name" },
          { name: "sort", in: "query", schema: { enum: ["risk", "recent"], default: "risk" } },
          { name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } }, { name: "pageSize", in: "query", schema: { type: "integer", minimum: 1, maximum: 100, default: 25 } },
        ],
        responses: { "200": json({ type: "object", required: ["items", "total", "page", "pageSize"], properties: { items: { type: "array", items: ref("Finding") }, total: { type: "integer" }, page: { type: "integer" }, pageSize: { type: "integer" } } }) },
      }) },
      "/findings/{id}": {
        get: op("viewer", "One finding with evidence, fix guidance and mapped controls", { parameters: [idParam], responses: { "200": json(ref("FindingDetail")), "404": err("No such finding") } }),
        patch: op("analyst", "Accept a risk, mark a false positive, or reopen", {
          parameters: [idParam],
          requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["status"], properties: { status: { enum: ["open", "accepted", "false_positive"] }, reason: { type: "string", minLength: 5, maxLength: 500, description: "Required unless reopening" }, acceptedUntil: { type: "string", format: "date-time", description: "Required for accepted; at most one year ahead" } } } } } },
          responses: { "200": json({ type: "object", properties: { ok: { const: true } } }), "400": err("A reason or expiry is missing"), "404": err("No such finding, or it is already fixed") },
        }),
      },
      "/assets": { get: op("viewer", "Asset inventory with open-finding counts", { parameters: [{ name: "type", in: "query", schema: { type: "string" } }, { name: "q", in: "query", schema: { type: "string" } }], responses: { "200": json({ type: "object", properties: { items: { type: "array", items: ref("Asset") }, types: { type: "array", items: { type: "object", properties: { type: { type: "string" }, n: { type: "integer" } } } } } }) } }) },
      "/compliance": { get: op("viewer", "Open findings mapped to frameworks (indicative, not an audit)", { responses: { "200": json({ type: "object", properties: { frameworks: { type: "array", items: { type: "object", properties: { framework: { type: "string" }, controls: { type: "integer" }, failed: { type: "integer" }, coverage: { type: "integer" } }, additionalProperties: true } }, ruleTitles: { type: "object", additionalProperties: { type: "string" } }, note: { type: "string" } } }) } }) },
      "/attack-paths": { get: op("viewer", "Ranked attack paths and the fixes that break the most of them", { responses: { "200": json(ref("AttackPaths")) } }) },
      "/scans": {
        get: op("viewer", "Scan history (latest 100)", { responses: { "200": json({ type: "object", properties: { items: { type: "array", items: ref("Scan") } } }) } }),
        post: op("analyst", "Run a scan of a pasted configuration", {
          description: "Uses one scan of the monthly quota. The configuration is an array of resources or `{ \"resources\": [...] }`.",
          requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["config"], properties: { config: { description: "Resources to evaluate", oneOf: [{ type: "array", items: { type: "object" } }, { type: "object" }] } } } } } },
          responses: { "201": json(ref("ScanResult"), "Scan completed"), "400": err("The configuration is not valid"), "402": err("Monthly scan quota used up") },
        }),
      },
      "/scans/{id}": { get: op("viewer", "One scan with its findings", { parameters: [idParam], responses: { "200": json({ allOf: [ref("Scan"), { type: "object", properties: { findings: { type: "array", items: { type: "object", additionalProperties: true } } } }] }), "404": err("No such scan") } }) },
      "/cloud-accounts": { get: op("viewer", "Connected AWS accounts and their status", { responses: { "200": json({ type: "object", properties: { items: { type: "array", items: { type: "object", additionalProperties: true } }, connector: { type: "object", additionalProperties: true } } }) } }) },
      "/cloud-accounts/{id}/scan": { post: op("analyst", "Scan a connected AWS account now", { parameters: [idParam], responses: { "201": json(ref("ScanResult"), "Scan completed"), "402": err("Monthly scan quota used up"), "409": err("A scan of this account is already running"), "404": err("No such account") } }) },
      "/suppressions": { get: op("analyst", "Rule suppressions in force", { responses: { "200": json({ type: "object", properties: { items: { type: "array", items: { type: "object", additionalProperties: true } } } }) } }) },
      "/usage": { get: op("viewer", "Plan, monthly scan and AI usage", { responses: { "200": json({ type: "object", additionalProperties: true }) } }) },
      "/reports/summary.csv": { get: op("viewer", "All findings as CSV", { responses: { "200": { description: "CSV file", content: { "text/csv": { schema: { type: "string" } } } } } }) },
      "/terraform/check": { post: op("viewer", "Check a Terraform plan before apply", {
        description: "Send `terraform show -json` output (or use deploy/tf-check.mjs, which sends only what the rules read). Nothing is stored and no scan is used. Up to 8 MB; 60 checks an hour.",
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["plan"], properties: { plan: { type: "object", description: "Terraform plan in JSON" }, failOn: { ...SEV, default: "high" } } } } } },
        responses: { "200": json(ref("TerraformCheck")), "400": err("Not a Terraform plan in JSON"), "413": err("Larger than 8 MB") },
      }) },
    },
    components: {
      securitySchemes: { apiKey: { type: "http", scheme: "bearer", description: "A key from Settings → API keys, starting `cspm_`" } },
      schemas: {
        Error: { type: "object", required: ["error"], properties: { error: { type: "object", required: ["code", "message"], properties: { code: { type: "string" }, message: { type: "string" } } } } },
        Finding: { type: "object", properties: { id: { type: "string", format: "uuid" }, title: { type: "string" }, severity: SEV, riskScore: { type: "integer", minimum: 0, maximum: 100 }, status: { enum: ["open", "fixed", "accepted", "false_positive"] }, ruleId: { enum: RULES.map((r) => r.id) }, firstSeenAt: { type: "string", format: "date-time" }, lastSeenAt: { type: "string", format: "date-time" }, assetName: { type: "string" }, assetType: { type: "string" }, provider: { type: "string" }, environment: { enum: ["production", "staging", "development"] } } },
        FindingDetail: { allOf: [ref("Finding"), { type: "object", properties: { evidence: { type: "object" }, remediation: { type: "string" }, frameworks: { type: "array", items: { type: "string" } }, statusReason: { type: ["string", "null"] }, acceptedUntil: { type: ["string", "null"], format: "date-time" }, suppressionId: { type: ["string", "null"], format: "uuid" }, assetId: { type: "string", format: "uuid" } } }] },
        Asset: { type: "object", properties: { id: { type: "string", format: "uuid" }, name: { type: "string" }, type: { type: "string" }, provider: { type: "string" }, environment: { type: "string" }, criticality: { type: "integer" }, owner: { type: ["string", "null"] }, lastSeenAt: { type: "string", format: "date-time" }, openFindings: { type: "integer" }, maxRisk: { type: "integer" } } },
        Scan: { type: "object", properties: { id: { type: "string", format: "uuid" }, source: { enum: ["paste", "account"] }, status: { type: "string" }, resourceCount: { type: "integer" }, findingCount: { type: "integer" }, score: { type: "integer" }, counts: { type: "object", additionalProperties: true }, createdAt: { type: "string", format: "date-time" } } },
        ScanResult: { type: "object", properties: { id: { type: "string", format: "uuid" }, resourceCount: { type: "integer" }, findingCount: { type: "integer" }, score: { type: "integer", description: "Posture 0-100, higher is safer" }, counts: { type: "object", properties: { new: { type: "integer" }, fixed: { type: "integer" }, persisting: { type: "integer" }, suppressed: { type: "integer" }, open: { type: "object", additionalProperties: { type: "integer" } } } }, unknownTypes: { type: "array", items: { type: "string" } } } },
        Overview: { type: "object", properties: { hasData: { type: "boolean" }, score: { type: "integer" }, delta: { type: ["integer", "null"] }, counts: { type: "object", additionalProperties: { type: "integer" } }, openTotal: { type: "integer" }, trend: { type: "array", items: { type: "object", additionalProperties: true } }, topActions: { type: "array", items: { type: "object", additionalProperties: true } } }, additionalProperties: true },
        AttackPaths: { type: "object", properties: { paths: { type: "array", items: { type: "object", additionalProperties: true } }, chokePoints: { type: "array", items: { type: "object", additionalProperties: true } }, coverage: { type: "object", additionalProperties: true }, notes: { type: "array", items: { type: "string" } }, assetCount: { type: "integer" } } },
        TerraformCheck: { type: "object", properties: { resourceCount: { type: "integer" }, counts: { type: "object", additionalProperties: { type: "integer" } }, score: { type: "integer" }, suppressed: { type: "integer" }, failOn: SEV, fail: { type: "boolean" }, findings: { type: "array", items: { type: "object", properties: { ruleId: { type: "string" }, title: { type: "string" }, severity: SEV, riskScore: { type: "integer" }, address: { type: "string" }, resourceType: { type: "string" }, evidence: { type: "object" }, remediation: { type: "string" } } } }, skipped: { type: "array", items: { type: "object", properties: { type: { type: "string" }, count: { type: "integer" } } } }, notes: { type: "array", items: { type: "string" } } } },
      },
    },
  };
}
