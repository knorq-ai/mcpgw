[English](./README.md) | [日本語](./README.ja.md)

# mcpgw

Security gateway for Model Context Protocol (MCP) servers. Intercepts JSON-RPC traffic between clients and MCP servers to enforce policies, authenticate requests, and produce audit logs.

## Overview

MCP allows AI agents to call external tools, but provides no built-in mechanism for access control or observability. mcpgw sits between the client and the MCP server as a transparent proxy, applying policy rules, authentication, rate limiting, and audit logging to every JSON-RPC message.

Two operating modes:

- **`proxy`** — HTTP reverse proxy for MCP Streamable HTTP transport (with optional TLS termination)
- **`wrap`** — stdio proxy that wraps an MCP server process and intercepts stdin/stdout

## Quick Start

```bash
go install github.com/yuyamorita/mcpgw@latest

# HTTP proxy mode
mcpgw proxy --upstream http://localhost:8080 --policy policy.yaml

# stdio wrap mode
mcpgw wrap --policy policy.yaml -- npx @modelcontextprotocol/server-everything
```

## Configuration

All options can be set via CLI flags, config file (`~/.mcpgw/config.yaml` or `--config`), or environment variables. CLI flags take precedence.

```yaml
upstream: http://localhost:8080
listen: ":9090"
policy: /etc/mcpgw/policy.yaml
audit_log: /var/log/mcpgw/audit.jsonl

tls:
  cert_file: /etc/mcpgw/cert.pem
  key_file: /etc/mcpgw/key.pem

auth:
  jwt:
    algorithm: HS256
    secret: ${MCPGW_JWT_SECRET}
  api_keys:
    - key: ${MCPGW_API_KEY_1}
      name: ci-agent

rate_limit:
  requests_per_second: 100
  burst: 20

session:
  ttl: "30m"

logging:
  level: info
  format: text

metrics:
  addr: ":9091"

cors:
  allowed_origins:
    - "http://example.com"

transport:
  max_idle_conns: 100
  max_idle_conns_per_host: 10
  idle_conn_timeout: "90s"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `upstream` | string | *(required for proxy)* | Upstream MCP server URL |
| `listen` | string | `:9090` | Listen address |
| `policy` | string | | Policy YAML file path |
| `audit_log` | string | `~/.mcpgw/audit.jsonl` | Audit log file path (JSONL, auto-rotated at 10MB) |
| `tls.cert_file` | string | | TLS certificate (must be paired with `key_file`) |
| `tls.key_file` | string | | TLS private key (must be paired with `cert_file`) |
| `auth.jwt.algorithm` | string | | `HS256`, `RS256`, or `ES256` |
| `auth.jwt.secret` | string | | HMAC secret for HS256 (env: `MCPGW_JWT_SECRET`) |
| `auth.jwt.pubkey_file` | string | | Public key PEM for RS256/ES256 |
| `auth.api_keys` | list | | Static API keys (`X-API-Key` header or `Authorization: ApiKey ...`) |
| `rate_limit.requests_per_second` | float | | Token bucket refill rate |
| `rate_limit.burst` | int | *(= requests_per_second)* | Token bucket capacity |
| `session.ttl` | string | `30m` | Idle session timeout (`time.ParseDuration` format) |
| `logging.level` | string | `info` | Log level (`debug`/`info`/`warn`/`error`) |
| `logging.format` | string | `text` | Log format (`text`/`json`) |
| `metrics.addr` | string | | Management server address (enables `/healthz` and `/metrics`) |
| `cors.allowed_origins` | list | | Allowed CORS origins (`*` for all) |
| `transport.max_idle_conns` | int | `100` | Max idle connections to upstream |
| `transport.max_idle_conns_per_host` | int | `10` | Max idle connections per host |
| `transport.idle_conn_timeout` | string | `90s` | Idle connection timeout |

## Policy

Policies are YAML files evaluated in first-match-wins order. Unmatched requests are implicitly denied.

```yaml
version: v1
mode: enforce   # "enforce" or "audit" (log-only, never blocks)
rules:
  - name: admin-exec
    match:
      methods: ["tools/call"]
      tools: ["exec_*"]
      subjects: ["admin-*"]
    action: allow

  - name: deny-exec
    match:
      methods: ["tools/call"]
      tools: ["exec_*"]
    action: deny

  - name: default-allow
    match:
      methods: ["*"]
    action: allow
```

| Field | Description |
|-------|-------------|
| `match.methods` | JSON-RPC method glob patterns (e.g., `tools/call`, `*`) |
| `match.tools` | MCP tool name glob patterns (only evaluated for `tools/call`) |
| `match.subjects` | Identity subject glob patterns (from JWT `sub` claim or API key name) |

Validate a policy file without starting the server:

```bash
mcpgw policy validate policy.yaml
```

### Hot Reload

Send `SIGHUP` to reload the policy file without downtime:

```bash
kill -HUP $(pgrep mcpgw)
```

If the new file is invalid, the old policy remains active and an error is logged to stderr.

## How It Works

```
Client ──► [CORS middleware] ──► [mcpgw proxy/wrap] ──► Upstream MCP Server
                                        │
                                        ├─ X-Request-Id propagation
                                        ├─ Auth middleware (JWT / API key validation)
                                        ├─ Interceptor chain:
                                        │   ├─ Rate limiter (token bucket)
                                        │   └─ Policy engine (first-match-wins rules)
                                        ├─ Audit logger (JSONL)
                                        ├─ Batch JSON-RPC support
                                        └─ SIGHUP → atomic policy engine swap

Management server (:9091) ──► /healthz, /metrics (Prometheus)
```

- Every JSON-RPC message (client-to-server) passes through the interceptor chain before forwarding
- Server-to-client messages also pass through the interceptor chain (SSE events are inspected individually)
- Batch JSON-RPC requests are supported — each message in the batch is individually filtered
- The policy engine uses `atomic.Pointer` for lock-free hot reload — zero downtime on `SIGHUP`
- Audit log entries include timestamp, direction, method, action (pass/block), reason, and `request_id`
- `X-Request-Id` is propagated through the entire request chain (auto-generated if missing)

## CLI

| Command | Description |
|---------|-------------|
| `mcpgw proxy` | Start HTTP reverse proxy |
| `mcpgw wrap -- <cmd> [args]` | Start stdio proxy wrapping a child process |
| `mcpgw policy validate <file>` | Validate a policy YAML file |
| `mcpgw version` | Print version |

### `proxy` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--upstream` | | Upstream MCP server URL |
| `--listen` | `:9090` | Listen address |
| `--policy` | | Policy YAML file path |
| `--audit-log` | `~/.mcpgw/audit.jsonl` | Audit log path |
| `--tls-cert` | | TLS certificate file |
| `--tls-key` | | TLS private key file |
| `--auth-jwt-algorithm` | | JWT algorithm (`HS256`/`RS256`/`ES256`) |
| `--auth-jwt-secret` | | JWT HMAC secret |
| `--auth-jwt-pubkey` | | JWT public key PEM file |
| `--auth-apikeys` | | Comma-separated API keys |
| `--config` | | Config file path |

### `wrap` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | | Policy YAML file path |
| `--audit-log` | `~/.mcpgw/audit.jsonl` | Audit log path |

## License

Apache License 2.0
