import { explain, type Finding } from "@workspace/cspm-engine";
import { config } from "../config";

type F = Pick<Finding, "ruleId" | "title" | "resourceName" | "resourceType" | "riskScore" | "evidence" | "remediation" | "frameworks">;

/** Anthropic when ANTHROPIC_API_KEY is set; otherwise (or on any failure) the deterministic, evidence-only text. */
export async function explainFinding(f: F): Promise<{ text: string; model: string }> {
  const base = explain(f);
  if (!config.anthropicKey) return { text: base, model: "rules" };
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": config.anthropicKey, "anthropic-version": "2023-06-01" },
      signal: AbortSignal.timeout(20_000),
      body: JSON.stringify({
        model: config.anthropicModel, max_tokens: 700,
        system: "You are a cloud security assistant inside a CSPM product. Use ONLY the facts given. If something is not in the facts, say it is not known. Write: a two-sentence plain-language summary for a manager, then numbered technical fix steps. No markdown headings. Never invent resource names, counts or incidents.",
        messages: [{ role: "user", content: JSON.stringify({ finding: f, draft: base }) }],
      }),
    });
    if (!res.ok) return { text: base, model: "rules" };
    const j: any = await res.json();
    const text = j?.content?.find?.((c: any) => c.type === "text")?.text;
    return text ? { text: String(text).slice(0, 4000), model: config.anthropicModel } : { text: base, model: "rules" };
  } catch { return { text: base, model: "rules" }; }
}
