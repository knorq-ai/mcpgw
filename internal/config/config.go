package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config はアプリケーション設定。
type Config struct {
	Upstream       string               `yaml:"upstream"`
	Listen         string               `yaml:"listen"`
	Policy         string               `yaml:"policy"`
	AuditLog       string               `yaml:"audit_log"`
	Routes         []RouteConfig        `yaml:"routes,omitempty"`
	Auth           AuthConfig           `yaml:"auth"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit"`
	Session        SessionConfig        `yaml:"session"`
	TLS            TLSConfig            `yaml:"tls"`
	Logging        LoggingConfig        `yaml:"logging"`
	Metrics        MetricsConfig        `yaml:"metrics"`
	CORS           CORSConfig           `yaml:"cors"`
	Transport      TransportConfig      `yaml:"transport"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
	ToolRateLimit  ToolRateLimitConfig  `yaml:"tool_rate_limit"`
	Alerting       AlertingConfig       `yaml:"alerting"`
	Telemetry      TelemetryConfig      `yaml:"telemetry,omitempty"`
	DrainTimeout   string               `yaml:"drain_timeout,omitempty"`
	Plugins        []PluginConfig       `yaml:"plugins,omitempty"`
	ServerEval     ServerEvalConfig     `yaml:"server_eval,omitempty"`
}

// ServerEvalConfig は MCP サーバー評価の設定。
type ServerEvalConfig struct {
	Enabled     bool              `yaml:"enabled"`
	Mode        string            `yaml:"mode"` // "enforce" or "audit"
	Allowlist   []ServerEntry     `yaml:"allowlist"`
	AutoApprove AutoApproveConfig `yaml:"auto_approve"`
	Webhook     string            `yaml:"webhook"`
}

// ServerEntry は許可リストのエントリ。
type ServerEntry struct {
	Name       string `yaml:"name"`
	Upstream   string `yaml:"upstream"` // glob パターン
	Status     string `yaml:"status"`   // "approved"|"denied"|"pending"
	ApprovedBy string `yaml:"approved_by"`
	ApprovedAt string `yaml:"approved_at"`
}

// AutoApproveConfig は自動承認の設定。
type AutoApproveConfig struct {
	RiskLevels []string `yaml:"risk_levels"`
}

// RouteConfig はツールベースのルーティングルール。
type RouteConfig struct {
	MatchTools []string `yaml:"match_tools"`
	Upstream   string   `yaml:"upstream"`
}

// PluginConfig はプラグインの設定。
type PluginConfig struct {
	Name   string         `yaml:"name"`
	Config map[string]any `yaml:"config,omitempty"`
}

// LoggingConfig はログ出力の設定。
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug/info/warn/error, デフォルト info
	Format string `yaml:"format"` // json/text, デフォルト text
}

// MetricsConfig はメトリクス公開の設定。
type MetricsConfig struct {
	Addr          string `yaml:"addr"`           // 管理サーバーアドレス (例: ":9091")
	AllowExternal bool   `yaml:"allow_external"` // true のとき全インターフェースにバインド（デフォルト: false = 127.0.0.1 のみ）
	APIKey        string `yaml:"api_key"`        // 管理 API の認証キー（空の場合は認証なし）
}

// TelemetryConfig は分散トレーシングの設定。
type TelemetryConfig struct {
	OTLPEndpoint string  `yaml:"otlp_endpoint"` // OTLP エクスポーター宛先（空の場合は no-op）
	ServiceName  string  `yaml:"service_name"`  // サービス名（デフォルト: "mcpgw"）
	SampleRate   float64 `yaml:"sample_rate"`   // サンプリング率 0.0–1.0（デフォルト: 1.0）
}

// CORSConfig は CORS の設定。
type CORSConfig struct {
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// TransportConfig は upstream 接続プールの設定。
type TransportConfig struct {
	MaxIdleConns        int    `yaml:"max_idle_conns"`
	MaxIdleConnsPerHost int    `yaml:"max_idle_conns_per_host"`
	IdleConnTimeout     string `yaml:"idle_conn_timeout"`
	RequestTimeout      string `yaml:"request_timeout"`
	SSEIdleTimeout      string `yaml:"sse_idle_timeout"`
}

// CircuitBreakerConfig はサーキットブレーカーの設定。
type CircuitBreakerConfig struct {
	MaxFailures int    `yaml:"max_failures"`
	Timeout     string `yaml:"timeout"`
}

// TLSConfig は TLS 終端の設定。
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// AuthConfig は認証関連の設定。
type AuthConfig struct {
	JWT     JWTAuthConfig   `yaml:"jwt"`
	APIKeys []APIKeyConfig  `yaml:"api_keys"`
	OAuth   OAuthAuthConfig `yaml:"oauth,omitempty"`
}

// OAuthAuthConfig は OAuth 2.1 / JWKS 認証の設定。
type OAuthAuthConfig struct {
	JWKSURL     string `yaml:"jwks_url"`
	Issuer      string `yaml:"issuer"`
	Audience    string `yaml:"audience,omitempty"`
	ResourceURL string `yaml:"resource_url,omitempty"`
}

// JWTAuthConfig は JWT 認証の設定。
type JWTAuthConfig struct {
	Algorithm  string `yaml:"algorithm"`
	Secret     string `yaml:"secret"`
	PubkeyFile string `yaml:"pubkey_file"`
	RolesClaim string `yaml:"roles_claim,omitempty"` // ロール抽出元の JWT claim 名（デフォルト: "roles"）
}

// APIKeyConfig は API キーの設定。
type APIKeyConfig struct {
	Key  string `yaml:"key"`
	Name string `yaml:"name"`
}

// RateLimitConfig はレート制限の設定。
type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

// ToolRateLimitConfig はツール単位のレート制限設定。
type ToolRateLimitConfig struct {
	RequestsPerMinute float64 `yaml:"requests_per_minute"`
	Burst             int     `yaml:"burst"`
}

// AlertingConfig はアラート通知の設定。
type AlertingConfig struct {
	WebhookURL  string `yaml:"webhook_url"`
	DedupWindow string `yaml:"dedup_window"` // time.ParseDuration 形式（例: "5m"）
}

// SessionConfig はセッション関連の設定。
type SessionConfig struct {
	TTL string `yaml:"ttl"` // time.ParseDuration 形式（例: "30m"）
}

// Load は設定ファイルを読み込む。
// path が空の場合は ~/.mcpgw/config.yaml を試行し、存在しなければ空の Config を返す。
// MCPGW_CONFIG 環境変数でもパス指定可能。
func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("MCPGW_CONFIG")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return &Config{}, nil
		}
		defaultPath := filepath.Join(home, ".mcpgw", "config.yaml")
		if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
			return &Config{}, nil
		}
		path = defaultPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	return Parse(data)
}

// Parse はバイト列を Config としてパースする。
// ${VAR} 形式の環境変数を展開する。
func Parse(data []byte) (*Config, error) {
	expanded := os.Expand(string(data), os.Getenv)

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}
