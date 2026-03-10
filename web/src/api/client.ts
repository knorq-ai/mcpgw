import type {
  StatsResponse,
  AuditResponse,
  PolicyResponse,
  StatusResponse,
  ServersResponse,
  AnalyticsResponse,
} from "./types";

const BASE = "";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export function fetchStats(): Promise<StatsResponse> {
  return get("/api/stats");
}

export function fetchAudit(params?: {
  limit?: number;
  offset?: number;
  method?: string;
  action?: string;
  direction?: string;
  subject?: string;
  upstream?: string;
  tool?: string;
}): Promise<AuditResponse> {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  if (params?.method) q.set("method", params.method);
  if (params?.action) q.set("action", params.action);
  if (params?.direction) q.set("direction", params.direction);
  if (params?.subject) q.set("subject", params.subject);
  if (params?.upstream) q.set("upstream", params.upstream);
  if (params?.tool) q.set("tool", params.tool);
  const qs = q.toString();
  return get(`/api/audit${qs ? `?${qs}` : ""}`);
}

export function fetchPolicy(): Promise<PolicyResponse> {
  return get("/api/policy");
}

export function fetchStatus(): Promise<StatusResponse> {
  return get("/api/status");
}

export function fetchServers(): Promise<ServersResponse> {
  return get("/api/servers");
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export function approveServer(upstream: string): Promise<{ status: string }> {
  return post("/api/servers/approve", { upstream });
}

export function denyServer(upstream: string): Promise<{ status: string }> {
  return post("/api/servers/deny", { upstream });
}

export function fetchAnalytics(
  dimension: string,
  params?: { from?: string; to?: string }
): Promise<AnalyticsResponse> {
  const q = new URLSearchParams();
  if (params?.from) q.set("from", params.from);
  if (params?.to) q.set("to", params.to);
  const qs = q.toString();
  return get(`/api/analytics/${dimension}${qs ? `?${qs}` : ""}`);
}
