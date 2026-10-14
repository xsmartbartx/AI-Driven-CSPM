import { createHash, createHmac, randomBytes, scrypt as _scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
const scrypt = promisify(_scrypt) as (p: string, s: Buffer, n: number) => Promise<Buffer>;

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return `s1$${salt.toString("hex")}$${h.toString("hex")}`;
}
export async function verifyPassword(pw: string, stored: string | null): Promise<boolean> {
  if (!stored) { await scrypt(pw, Buffer.alloc(16), 64); return false; } // keep timing similar
  const [v, s, h] = stored.split("$");
  if (v !== "s1" || !s || !h) return false;
  const got = await scrypt(pw, Buffer.from(s, "hex"), 64);
  const want = Buffer.from(h, "hex");
  return got.length === want.length && timingSafeEqual(got, want);
}

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
export function signJwt(payload: Record<string, unknown>, secret: string, ttlSec: number): string {
  const head = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64u(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSec }));
  const sig = b64u(createHmac("sha256", secret).update(`${head}.${body}`).digest());
  return `${head}.${body}.${sig}`;
}
export function verifyJwt<T = Record<string, any>>(token: string, secret: string): T | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, b, s] = parts as [string, string, string];
  try {
    if (JSON.parse(Buffer.from(h, "base64url").toString()).alg !== "HS256") return null;
    const want = createHmac("sha256", secret).update(`${h}.${b}`).digest();
    const got = Buffer.from(s, "base64url");
    if (got.length !== want.length || !timingSafeEqual(got, want)) return null;
    const p = JSON.parse(Buffer.from(b, "base64url").toString());
    if (typeof p.exp !== "number" || p.exp < Date.now() / 1000) return null;
    return p as T;
  } catch { return null; }
}
export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const randomToken = (bytes = 24) => randomBytes(bytes).toString("base64url");
export function verifyHmacHex(secret: string, payload: string, hex: string): boolean {
  const want = createHmac("sha256", secret).update(payload).digest();
  let got: Buffer; try { got = Buffer.from(hex, "hex"); } catch { return false; }
  return got.length === want.length && timingSafeEqual(got, want);
}
