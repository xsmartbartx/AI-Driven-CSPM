import { openDb } from "@workspace/db";
import { createApp } from "./app";
import { config } from "./config";
import { logger } from "./lib/logger";
import { createAwsConnector, disabledAwsConnector } from "./services/aws/connector";
import { createMailer } from "./services/mail";
import { startScheduler } from "./services/scheduler";

if (!config.rls) logger.warn("RLS_ENFORCE=0: running WITHOUT database-level tenant isolation");
const db = await openDb({ url: config.databaseUrl, dataDir: config.dataDir, rls: config.rls, poolMax: config.poolMax });
const aws = config.awsAccountId ? createAwsConnector(config.awsAccountId) : disabledAwsConnector;
const mailer = createMailer();
const app = createApp(db, { aws, mailer });
const scheduler = config.scheduler ? startScheduler({ db, aws, mailer }, config.schedulerTickSeconds * 1000) : null;
if (scheduler) logger.info({ everySeconds: config.schedulerTickSeconds }, "scheduler started");
const server = app.listen(config.port, (err?: Error) => {
  if (err) { logger.error({ err }, "Error listening on port"); process.exit(1); }
  logger.info({ port: config.port, db: config.databaseUrl ? "postgres" : "pglite" }, "Server listening");
});
for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, () => { void (async () => { await scheduler?.stop(); server.close(() => void db.close().finally(() => process.exit(0))); })(); });
