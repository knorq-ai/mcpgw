import type {
  StatsResponse,
  AuditResponse,
  PolicyResponse,
  StatusResponse,
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
}): Promise<AuditResponse> {
  const q = new URLSearchParams();
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  if (params?.method) q.set("method", params.method);
  if (params?.action) q.set("action", params.action);
  if (params?.direction) q.set("direction", params.direction);
  const qs = q.toString();
  return get(`/api/audit${qs ? `?${qs}` : ""}`);
}

export function fetchPolicy(): Promise<PolicyResponse> {
  return get("/api/policy");
}

export function fetchStatus(): Promise<StatusResponse> {
  return get("/api/status");
}
