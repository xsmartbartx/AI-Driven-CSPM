import { useCallback, useEffect, useState } from "react";

const BASE = ((import.meta as any).env?.VITE_API_URL ?? "") + "/api";
export const apiUrl = (p: string) => BASE + p;

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}

export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, {
      method, credentials: "include",
      headers: { "content-type": "application/json", "x-csrf": "1" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "network", "Cannot reach the server. Check your connection and try again.");
  }
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  if (!res.ok) throw new ApiError(res.status, json?.error?.code ?? "error", json?.error?.message ?? `Request failed (${res.status})`);
  return json as T;
}

export function useApi<T = any>(path: string | null) {
  const [state, set] = useState<{ data: T | null; error: ApiError | null; loading: boolean }>({ data: null, error: null, loading: !!path });
  const load = useCallback(async () => {
    if (!path) return;
    set((s) => ({ ...s, loading: true, error: null }));
    try { set({ data: await api<T>("GET", path), error: null, loading: false }); }
    catch (e) { set({ data: null, error: e as ApiError, loading: false }); }
  }, [path]);
  useEffect(() => { void load(); }, [load]);
  return { ...state, reload: load };
}
