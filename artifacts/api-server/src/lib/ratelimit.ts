import type { Request, Response, NextFunction } from "express";
import { HttpError } from "./errors";

// In-memory, per process. Behind several instances, move this to Redis.
const hits = new Map<string, number[]>();
export function rateLimit(name: string, max: number, windowMs: number, keyOf: (req: Request) => string = (r) => r.ip ?? "?") {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (process.env["RATE_LIMIT_DISABLED"] === "1" && process.env["NODE_ENV"] !== "production") return next(); // e2e only
    const key = `${name}:${keyOf(req)}`;
    const now = Date.now();
    const arr = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
    if (arr.length >= max) throw new HttpError(429, "rate_limited", "Too many requests. Try again later.");
    arr.push(now);
    hits.set(key, arr);
    next();
  };
}
export function resetRateLimits() { hits.clear(); }
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.every((t) => now - t > 3600_000)) hits.delete(k); }, 600_000).unref();
