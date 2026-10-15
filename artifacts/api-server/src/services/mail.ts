import { config } from "../config";
import { logger } from "../lib/logger";

export interface Mail { to: string; subject: string; text: string; html: string }
export interface Mailer {
  /** false when mail cannot be delivered (production without a provider key) */
  enabled: boolean;
  /** Never throws: a mail failure must not fail the request that triggered it. Returns whether it was handed to the provider. */
  send(m: Mail): Promise<boolean>;
}

/** Resend over plain HTTPS. https://resend.com/docs/api-reference/emails/send-email */
export function resendMailer(apiKey: string, from: string, fetchImpl: typeof fetch = fetch): Mailer {
  return {
    enabled: true,
    async send(m) {
      try {
        const res = await fetchImpl("https://api.resend.com/emails", {
          method: "POST",
          headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
          body: JSON.stringify({ from, to: [m.to], subject: m.subject, text: m.text, html: m.html }),
          signal: AbortSignal.timeout(10_000),
        });
        if (!res.ok) {
          // log the status only: the response and the message contain the recipient and a one-time link
          logger.error({ status: res.status }, "email provider rejected the message");
          return false;
        }
        return true;
      } catch (err) {
        logger.error({ err: (err as Error).name }, "email provider unreachable");
        return false;
      }
    },
  };
}

/** Development convenience: print the email, including its link, so flows can be tried without a provider. Never used in production. */
export function consoleMailer(): Mailer {
  return {
    enabled: true,
    async send(m) {
      console.log(`\n--- email to ${m.to} ---\n${m.subject}\n\n${m.text}\n---\n`);
      return true;
    },
  };
}

export function disabledMailer(): Mailer {
  return { enabled: false, async send() { logger.warn("email not configured (set RESEND_API_KEY); message not sent"); return false; } };
}

export function createMailer(): Mailer {
  if (config.resendKey) return resendMailer(config.resendKey, config.mailFrom);
  return config.prod ? disabledMailer() : consoleMailer();
}
