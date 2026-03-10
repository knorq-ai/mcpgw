export interface StatsResponse {
  requests_total: number;
  requests_blocked: number;
  blocked_rate: number;
  active_sessions: number;
  upstream_errors: number;
  circuit_breaker_trips: number;
  latency_p50: number;
  latency_p95: number;
  latency_p99: number;
  requests_by_method: Record<string, number>;
}

export interface AuditEntry {
  timestamp: string;
  direction: string;
  method: string;
  id: string;
  kind: string;
  size: number;
  action: string;
  reason: string;
  subject?: string;
  upstream?: string;
  request_id: string;
  tool_name: string;
  tool_args?: Record<string, unknown>;
}

export interface AuditResponse {
  entries: AuditEntry[];
  total: number;
}

export interface PolicyRule {
  name: string;
  methods: string[];
  tools?: string[];
  subjects?: string[];
  arguments?: Record<string, string[]>;
  argument_patterns?: Record<string, string[]>;
  action: string;
  mode?: string;
}

export interface PolicyResponse {
  version: string;
  mode: string;
  rules: PolicyRule[];
  response_patterns?: string[];
  allowed_tools?: string[];
}

export interface StatusResponse {
  upstream: string;
  upstream_ready: boolean;
  circuit_breaker: string;
  active_sessions: number;
}

export interface ToolInfo {
  name: string;
  risk_level: string;
}

export interface ServerInfo {
  upstream: string;
  server_name?: string;
  tools: ToolInfo[];
  risk_level: string;
  risk_score: number;
  status: string;
  discovered_at: string;
  evaluated_at: string;
}

export interface ServersResponse {
  servers: ServerInfo[];
}

export interface AnalyticsGroup {
  key: string;
  total: number;
  passed: number;
  blocked: number;
  block_rate: number;
  top_tools: string[];
  top_methods: string[];
}

export interface AnalyticsResponse {
  groups: AnalyticsGroup[];
  period: {
    from: string;
    to: string;
  };
}
