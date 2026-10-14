import type { Db } from "@workspace/db";
export type Role = "owner" | "admin" | "analyst" | "viewer";
export const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3, owner: 4 };
/** userId is null when the caller is an API key. */
export interface Auth { userId: string | null; orgId: string; role: Role; email: string | null; via: "session" | "key" }
declare global {
  namespace Express {
    interface Request { auth?: Auth; db: Db; rawBody?: Buffer }
  }
}
