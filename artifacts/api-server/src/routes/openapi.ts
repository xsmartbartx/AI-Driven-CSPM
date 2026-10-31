import { Router } from "express";
import { config } from "../config";
import { buildOpenApi } from "../openapi";

const r = Router();
const API_URL = process.env["API_PUBLIC_URL"] ?? (config.prod ? "https://api.cspm.onenexora.com/api" : "http://localhost:8080/api");

/** Public on purpose: the description of the API is not a secret, and tools read it without a key. */
r.get("/openapi.json", (_req, res) => {
  res.setHeader("cache-control", "public, max-age=300").json(buildOpenApi(API_URL));
});

export default r;
