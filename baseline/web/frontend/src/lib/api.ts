import { useAuth } from "./store";
import type { ApiError } from "./types";

// API_BASE is empty: all API requests go through the Vite dev server proxy
// (which forwards /ui/api/v1/* and /healthz to the Go backend on :8080).
// In production (Go embeds the frontend), requests are same-origin.
const API_BASE = "";

export class HttpError extends Error {
  code: string;
  status: number;
  retryable: boolean;
  constructor(status: number, code: string, message: string, retryable: boolean) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryable = retryable;
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>
): Promise<T> {
  const token = useAuth.getState().token;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (extraHeaders) Object.assign(headers, extraHeaders);

  const resp = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (resp.status === 204) return undefined as T;

  const text = await resp.text();
  if (resp.status >= 400) {
    let code = "UNKNOWN";
    let message = "request failed";
    let retryable = false;
    try {
      const err = JSON.parse(text) as ApiError;
      code = err.error?.code ?? code;
      message = err.error?.message ?? message;
      retryable = err.error?.retryable ?? false;
    } catch {
      // non-JSON error
    }
    throw new HttpError(resp.status, code, message, retryable);
  }

  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown, extraHeaders?: Record<string, string>) =>
    request<T>("POST", path, body, extraHeaders),
  patch: <T>(path: string, body?: unknown, extraHeaders?: Record<string, string>) =>
    request<T>("PATCH", path, body, extraHeaders),
  put: <T>(path: string, body?: unknown, extraHeaders?: Record<string, string>) =>
    request<T>("PUT", path, body, extraHeaders),
  delete: <T>(path: string, body?: unknown) => request<T>("DELETE", path, body),
};

// Health check (unauthenticated).
export async function healthCheck(): Promise<{ status: string }> {
  const resp = await fetch(`${API_BASE}/healthz`);
  return resp.json();
}
