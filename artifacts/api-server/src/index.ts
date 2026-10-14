import { openDb } from "@workspace/db";
import { createApp } from "./app";
import { config } from "./config";
import { logger } from "./lib/logger";

const db = await openDb({ url: config.databaseUrl, dataDir: config.dataDir });
const app = createApp(db);
const server = app.listen(config.port, (err?: Error) => {
  if (err) { logger.error({ err }, "Error listening on port"); process.exit(1); }
  logger.info({ port: config.port, db: config.databaseUrl ? "postgres" : "pglite" }, "Server listening");
});
for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => server.close(() => void db.close().finally(() => process.exit(0))));
