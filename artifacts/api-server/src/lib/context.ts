import type { Db } from "@workspace/db";
import type { Mailer } from "../services/mail";
export type Role = "owner" | "admin" | "analyst" | "viewer";
export const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3, owner: 4 };
/** userId is null when the caller is an API key. */
export interface Auth { userId: string | null; orgId: string; role: Role; email: string | null; via: "session" | "key" }
declare global {
  namespace Express {
    /** db is the privileged connection until requireRole() authenticates the request, then the caller's tenant-scoped view (RLS). */
    interface Request { auth?: Auth; db: Db; sysDb: Db; mailer: Mailer; rawBody?: Buffer }
  }
}
