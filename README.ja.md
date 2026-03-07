[English](./README.md) | [日本語](./README.ja.md)

# mcpgw

Model Context Protocol (MCP) サーバー向けセキュリティゲートウェイ。クライアントと MCP サーバー間の JSON-RPC 通信を傍受し、ポリシー適用・認証・監査ログを実現する。

## 概要

MCP は AI エージェントに外部ツール呼び出しを提供するが、アクセス制御や可観測性の仕組みを持たない。mcpgw はクライアントと MCP サーバーの間に透過プロキシとして配置され、すべての JSON-RPC メッセージにポリシールール・認証・レート制限・監査ログを適用する。

2 つの動作モード:

- **`proxy`** — MCP Streamable HTTP トランスポート用 HTTP リバースプロキシ（TLS 終端対応）
- **`wrap`** — MCP サーバープロセスを子プロセスとして起動し、stdin/stdout を傍受する stdio プロキシ

## Quick Start

```bash
go install github.com/knorq-ai/mcpgw@latest

# HTTP proxy モード
mcpgw proxy --upstream http://localhost:8080 --policy policy.yaml

# stdio wrap モード
mcpgw wrap --policy policy.yaml -- npx @modelcontextprotocol/server-everything
```

## 設定

すべてのオプションは CLI フラグ、設定ファイル（`~/.mcpgw/config.yaml` または `--config`）、環境変数で指定できる。CLI フラグが最優先。

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

| フィールド | 型 | デフォルト | 説明 |
|-----------|------|----------|------|
| `upstream` | string | *(proxy で必須)* | upstream MCP サーバーの URL |
| `listen` | string | `:9090` | リッスンアドレス |
| `policy` | string | | ポリシー YAML ファイルパス |
| `audit_log` | string | `~/.mcpgw/audit.jsonl` | 監査ログファイルパス（JSONL、10MB で自動ローテーション） |
| `tls.cert_file` | string | | TLS 証明書（`key_file` とペアで指定） |
| `tls.key_file` | string | | TLS 秘密鍵（`cert_file` とペアで指定） |
| `auth.jwt.algorithm` | string | | `HS256`、`RS256`、`ES256` |
| `auth.jwt.secret` | string | | HS256 用 HMAC シークレット（env: `MCPGW_JWT_SECRET`） |
| `auth.jwt.pubkey_file` | string | | RS256/ES256 用公開鍵 PEM ファイル |
| `auth.api_keys` | list | | 静的 API キー（`X-API-Key` ヘッダまたは `Authorization: ApiKey ...`） |
| `rate_limit.requests_per_second` | float | | トークンバケットのリフィルレート |
| `rate_limit.burst` | int | *(= requests_per_second)* | トークンバケット容量 |
| `session.ttl` | string | `30m` | アイドルセッションタイムアウト（`time.ParseDuration` 形式） |
| `logging.level` | string | `info` | ログレベル（`debug`/`info`/`warn`/`error`） |
| `logging.format` | string | `text` | ログフォーマット（`text`/`json`） |
| `metrics.addr` | string | | 管理サーバーアドレス（`/healthz` と `/metrics` を有効化） |
| `cors.allowed_origins` | list | | 許可する CORS オリジン（`*` で全許可） |
| `transport.max_idle_conns` | int | `100` | upstream への最大アイドル接続数 |
| `transport.max_idle_conns_per_host` | int | `10` | ホストごとの最大アイドル接続数 |
| `transport.idle_conn_timeout` | string | `90s` | アイドル接続タイムアウト |

## ポリシー

ポリシーは YAML ファイルで定義し、first-match-wins で評価される。どのルールにもマッチしないリクエストは暗黙的に拒否される。

```yaml
version: v1
mode: enforce   # "enforce" または "audit"（ログのみ、ブロックしない）
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

| フィールド | 説明 |
|-----------|------|
| `match.methods` | JSON-RPC メソッド名の glob パターン（例: `tools/call`、`*`） |
| `match.tools` | MCP ツール名の glob パターン（`tools/call` のみで評価） |
| `match.subjects` | Identity subject の glob パターン（JWT `sub` クレームまたは API キー名） |

ポリシーファイルの検証（サーバーを起動せずに実行可能）:

```bash
mcpgw policy validate policy.yaml
```

### ホットリロード

`SIGHUP` を送信すると、ダウンタイムなしでポリシーファイルを再読み込みする:

```bash
kill -HUP $(pgrep mcpgw)
```

新しいファイルが不正な場合、旧ポリシーが維持され、エラーが stderr に出力される。

## アーキテクチャ

```
Client ──► [CORS middleware] ──► [mcpgw proxy/wrap] ──► Upstream MCP Server
                                        │
                                        ├─ X-Request-Id 伝播
                                        ├─ Auth middleware (JWT / API key 検証)
                                        ├─ Interceptor chain:
                                        │   ├─ Rate limiter (token bucket)
                                        │   └─ Policy engine (first-match-wins ルール)
                                        ├─ Audit logger (JSONL)
                                        ├─ バッチ JSON-RPC サポート
                                        └─ SIGHUP → atomic policy engine swap

管理サーバー (:9091) ──► /healthz, /metrics (Prometheus)
```

- すべての JSON-RPC メッセージ（client-to-server）は interceptor chain を通過してから転送される
- Server-to-client メッセージは監査ログのため interceptor chain を通過するが、ポリシールールは client-to-server 方向のみ評価される（S→C はポリシーに対して fail-open）。SSE イベントは個別に検査される
- バッチ JSON-RPC リクエストに対応 — バッチ内の各メッセージが個別にフィルタリングされる
- ポリシーエンジンは `atomic.Pointer` によるロックフリーのホットリロードを実現 — `SIGHUP` でダウンタイムなし
- 監査ログエントリにはタイムスタンプ、方向、メソッド、アクション（pass/block）、理由、`request_id` が含まれる
- `X-Request-Id` はリクエストチェーン全体で伝播される（未指定の場合は自動生成）

## CLI

| コマンド | 説明 |
|---------|------|
| `mcpgw proxy` | HTTP リバースプロキシを起動 |
| `mcpgw wrap -- <cmd> [args]` | 子プロセスをラップする stdio プロキシを起動 |
| `mcpgw policy validate <file>` | ポリシー YAML ファイルを検証 |
| `mcpgw version` | バージョンを表示 |

### `proxy` フラグ

| フラグ | デフォルト | 説明 |
|-------|----------|------|
| `--upstream` | | upstream MCP サーバーの URL |
| `--listen` | `:9090` | リッスンアドレス |
| `--policy` | | ポリシー YAML ファイルパス |
| `--audit-log` | `~/.mcpgw/audit.jsonl` | 監査ログパス |
| `--tls-cert` | | TLS 証明書ファイル |
| `--tls-key` | | TLS 秘密鍵ファイル |
| `--auth-jwt-algorithm` | | JWT アルゴリズム（`HS256`/`RS256`/`ES256`） |
| `--auth-jwt-secret` | | JWT HMAC シークレット |
| `--auth-jwt-pubkey` | | JWT 公開鍵 PEM ファイル |
| `--auth-apikeys` | | カンマ区切りの API キー |
| `--config` | | 設定ファイルパス |

### `wrap` フラグ

| フラグ | デフォルト | 説明 |
|-------|----------|------|
| `--policy` | | ポリシー YAML ファイルパス |
| `--audit-log` | `~/.mcpgw/audit.jsonl` | 監査ログパス |

## License

Apache License 2.0
