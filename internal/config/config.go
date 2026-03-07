package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config はアプリケーション設定。
type Config struct {
	Upstream  string          `yaml:"upstream"`
	Listen    string          `yaml:"listen"`
	Policy    string          `yaml:"policy"`
	AuditLog  string          `yaml:"audit_log"`
	Auth      AuthConfig      `yaml:"auth"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Session   SessionConfig   `yaml:"session"`
	TLS       TLSConfig       `yaml:"tls"`
	Logging   LoggingConfig   `yaml:"logging"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	CORS      CORSConfig      `yaml:"cors"`
	Transport TransportConfig `yaml:"transport"`
}

// LoggingConfig はログ出力の設定。
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug/info/warn/error, デフォルト info
	Format string `yaml:"format"` // json/text, デフォルト text
}

// MetricsConfig はメトリクス公開の設定。
type MetricsConfig struct {
	Addr string `yaml:"addr"` // 管理サーバーアドレス (例: ":9091")
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
}

// TLSConfig は TLS 終端の設定。
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// AuthConfig は認証関連の設定。
type AuthConfig struct {
	JWT     JWTAuthConfig  `yaml:"jwt"`
	APIKeys []APIKeyConfig `yaml:"api_keys"`
}

// JWTAuthConfig は JWT 認証の設定。
type JWTAuthConfig struct {
	Algorithm string `yaml:"algorithm"`
	Secret    string `yaml:"secret"`
	PubkeyFile string `yaml:"pubkey_file"`
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
