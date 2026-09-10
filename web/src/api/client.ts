import type {
  ConfigResponse,
  DetectorInfo,
  EventsPage,
  Session,
  Status,
  Summary,
  TestResponse,
  Timeseries,
  ValidateResponse,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Raised on 401 so callers can send the viewer back to the login screen. */
export class UnauthorizedError extends ApiError {
  constructor(message = "authentication required") {
    super(401, message);
    this.name = "UnauthorizedError";
  }
}

export function readCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : "";
}

let onUnauthorized: (() => void) | undefined;

/** Registers the callback used when the API reports the session is gone. */
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  // The double-submit CSRF token: the cookie is readable, the header is not
  // something a cross-site form can set.
  if (method !== "GET" && method !== "HEAD") {
    const csrf = readCookie("aigk_csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    signal: opts.signal,
  });

  const text = await res.text();
  let body: unknown = undefined;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  if (res.status === 401) {
    onUnauthorized?.();
    throw new UnauthorizedError(messageOf(body) ?? "authentication required");
  }
  if (!res.ok) {
    throw new ApiError(res.status, messageOf(body) ?? `request failed with status ${res.status}`, body);
  }
  return body as T;
}

function messageOf(body: unknown): string | undefined {
  if (typeof body === "string") return body;
  if (body && typeof body === "object" && "error" in body) {
    const err = (body as { error: unknown }).error;
    if (typeof err === "string") return err;
  }
  return undefined;
}

function query(params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "" && v !== null) q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

export const api = {
  me: () => request<Session>("/api/v1/auth/me"),
  login: (credential: { password?: string; token?: string }) =>
    request<Session & { csrf_token: string }>("/api/v1/auth/login", { method: "POST", body: credential }),
  logout: () => request<unknown>("/api/v1/auth/logout", { method: "POST" }),

  status: () => request<Status>("/api/v1/status"),
  detectors: () => request<{ detectors: DetectorInfo[]; extractors: string[] }>("/api/v1/detectors"),

  config: () => request<ConfigResponse>("/api/v1/config"),
  validateConfig: (payload: { yaml?: string; config?: unknown }) =>
    request<ValidateResponse>("/api/v1/config/validate", { method: "POST", body: payload }),
  applyConfig: (payload: { yaml?: string; config?: unknown; base_version: string }) =>
    request<{ applied: boolean; version: string; loaded_at: string }>("/api/v1/config/apply", {
      method: "POST",
      body: payload,
    }),
  reload: () => request<{ reloaded: boolean; changed: boolean; version: string }>("/api/v1/reload", { method: "POST" }),

  test: (payload: { text?: string; body?: string; service?: string; path?: string; yaml?: string }) =>
    request<TestResponse>("/api/v1/test", { method: "POST", body: payload }),

  events: (params: {
    from?: string;
    to?: string;
    kind?: string;
    service?: string;
    action?: string;
    rule?: string;
    client?: string;
    host?: string;
    detector?: string;
    q?: string;
    cursor?: string;
    limit?: number;
  }) => request<EventsPage>(`/api/v1/events${query(params)}`),
  event: (id: number) => request<Record<string, unknown>>(`/api/v1/events/${id}`),

  summary: (range: string) => request<Summary>(`/api/v1/stats/summary${query({ range })}`),
  timeseries: (range: string, group: string) => request<Timeseries>(`/api/v1/stats/timeseries${query({ range, group })}`),
};
