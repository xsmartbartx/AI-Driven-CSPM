import express, { type Express, type NextFunction, type Request, type Response } from "express";
import cors from "cors";
import pinoHttp from "pino-http";
import type { Db } from "@workspace/db";
import { config } from "./config";
import { logger } from "./lib/logger";
import { HttpError } from "./lib/errors";
import { createMailer, type Mailer } from "./services/mail";
import { createAwsConnector, disabledAwsConnector } from "./services/aws/connector";
import type { AwsConnector } from "./services/aws/types";
import cloudRouter from "./routes/cloud";
import pathsRouter from "./routes/paths";
import notificationsRouter from "./routes/notifications";
import healthRouter from "./routes/health";
import authRouter from "./routes/auth";
import scansRouter from "./routes/scans";
import findingsRouter from "./routes/findings";
import teamRouter from "./routes/team";

export function createApp(db: Db, opts: { mailer?: Mailer; aws?: AwsConnector; fetch?: typeof fetch } = {}): Express {
  const mailer = opts.mailer ?? createMailer();
  const aws = opts.aws ?? (config.awsAccountId ? createAwsConnector(config.awsAccountId) : disabledAwsConnector);
  const app: Express = express();
  app.disable("x-powered-by");
  if (config.trustProxy) app.set("trust proxy", 1);

  app.use(pinoHttp({
    logger,
    serializers: {
      req: (req) => ({ id: req.id, method: req.method, url: req.url?.split("?")[0] }),
      res: (res) => ({ statusCode: res.statusCode }),
    },
  }));
  app.use((_req, res, next) => {
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("x-frame-options", "DENY");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    res.setHeader("cache-control", "no-store");
    if (config.prod) res.setHeader("strict-transport-security", "max-age=63072000; includeSubDomains");
    next();
  });
  // exact origins only, with credentials. Unlisted origins get no CORS headers.
  app.use(cors({ origin: (o, cb) => cb(null, !o || config.origins.includes(o)), credentials: true, allowedHeaders: ["content-type", "x-csrf", "authorization"], methods: ["GET", "POST", "PUT", "PATCH", "DELETE"] }));
  app.use(express.json({ limit: "1mb", verify: (req, _res, buf) => { (req as Request).rawBody = buf; } }));
  app.use((req, res, next) => {
    req.db = db; req.sysDb = db; req.mailer = mailer; req.aws = aws; req.notifyFetch = opts.fetch;
    // "close" also fires when the client disconnects mid-request: the final release waits for any query or transaction
    // still running, then returns the connection, and refuses further use by the abandoned handler
    res.on("close", () => { void req.db.release(true).catch(() => {}); });
    next();
  });

  app.use("/api", healthRouter, authRouter, scansRouter, findingsRouter, teamRouter, cloudRouter, pathsRouter, notificationsRouter);
  app.use("/api", (_req, _res, next) => next(new HttpError(404, "not_found", "Unknown endpoint")));

  app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) return void res.status(err.status).json({ error: { code: err.code, message: err.message } });
    if (err?.type === "entity.too.large") return void res.status(413).json({ error: { code: "too_large", message: "Request body is too large (limit 1 MB)" } });
    if (err?.type === "entity.parse.failed") return void res.status(400).json({ error: { code: "invalid_json", message: "Request body is not valid JSON" } });
    req.log?.error({ err }, "unhandled error");
    res.status(500).json({ error: { code: "internal", message: "Something went wrong" } });
  });
  return app;
}
