export class HttpError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}
export const bad = (m: string, code = "bad_request") => new HttpError(400, code, m);
export const unauthorized = (m = "Sign in required") => new HttpError(401, "unauthorized", m);
export const forbidden = (m = "You do not have permission to do this") => new HttpError(403, "forbidden", m);
export const notFound = (m = "Not found") => new HttpError(404, "not_found", m);
export const conflict = (m: string, code = "conflict") => new HttpError(409, code, m);
