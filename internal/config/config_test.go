package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBasic(t *testing.T) {
	data := []byte(`
upstream: http://localhost:8080
listen: ":9090"
policy: /etc/mcpgw/policy.yaml
audit_log: /var/log/mcpgw/audit.jsonl
auth:
  jwt:
    algorithm: HS256
    secret: my-secret
  api_keys:
    - key: key-alpha
      name: alpha
rate_limit:
  requests_per_second: 10.5
  burst: 20
session:
  ttl: "30m"
`)
	cfg, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080", cfg.Upstream)
	assert.Equal(t, ":9090", cfg.Listen)
	assert.Equal(t, "/etc/mcpgw/policy.yaml", cfg.Policy)
	assert.Equal(t, "/var/log/mcpgw/audit.jsonl", cfg.AuditLog)
	assert.Equal(t, "HS256", cfg.Auth.JWT.Algorithm)
	assert.Equal(t, "my-secret", cfg.Auth.JWT.Secret)
	require.Len(t, cfg.Auth.APIKeys, 1)
	assert.Equal(t, "key-alpha", cfg.Auth.APIKeys[0].Key)
	assert.Equal(t, "alpha", cfg.Auth.APIKeys[0].Name)
	assert.Equal(t, 10.5, cfg.RateLimit.RequestsPerSecond)
	assert.Equal(t, 20, cfg.RateLimit.Burst)
	assert.Equal(t, "30m", cfg.Session.TTL)
}

func TestParseEnvVarExpansion(t *testing.T) {
	t.Setenv("TEST_UPSTREAM", "http://env-host:8080")
	t.Setenv("TEST_SECRET", "env-secret-value")

	data := []byte(`
upstream: ${TEST_UPSTREAM}
auth:
  jwt:
    algorithm: HS256
    secret: ${TEST_SECRET}
`)
	cfg, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, "http://env-host:8080", cfg.Upstream)
	assert.Equal(t, "env-secret-value", cfg.Auth.JWT.Secret)
}

func TestParseEmptyConfig(t *testing.T) {
	cfg, err := Parse([]byte(""))
	require.NoError(t, err)
	assert.Equal(t, &Config{}, cfg)
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := Parse([]byte("invalid: yaml: content: ["))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse config")
}

func TestParsePartialConfig(t *testing.T) {
	data := []byte(`
upstream: http://localhost:8080
rate_limit:
  burst: 5
`)
	cfg, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:8080", cfg.Upstream)
	assert.Equal(t, "", cfg.Listen)
	assert.Equal(t, float64(0), cfg.RateLimit.RequestsPerSecond)
	assert.Equal(t, 5, cfg.RateLimit.Burst)
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`upstream: http://test:8080`), 0o600))

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "http://test:8080", cfg.Upstream)
}

func TestLoadEmptyPathNoDefault(t *testing.T) {
	// デフォルトファイルが存在しない場合は空 Config
	t.Setenv("MCPGW_CONFIG", "")
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, &Config{}, cfg)
}

func TestLoadFromEnvVar(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "env-config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`listen: ":7070"`), 0o600))

	t.Setenv("MCPGW_CONFIG", cfgPath)
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, ":7070", cfg.Listen)
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	assert.Error(t, err)
}

func TestParseNewConfigFields(t *testing.T) {
	data := []byte(`
upstream: http://localhost:8080
logging:
  level: debug
  format: json
metrics:
  addr: ":9091"
cors:
  allowed_origins:
    - "http://example.com"
    - "*"
transport:
  max_idle_conns: 200
  max_idle_conns_per_host: 20
  idle_conn_timeout: "120s"
`)
	cfg, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, ":9091", cfg.Metrics.Addr)
	require.Len(t, cfg.CORS.AllowedOrigins, 2)
	assert.Equal(t, "http://example.com", cfg.CORS.AllowedOrigins[0])
	assert.Equal(t, "*", cfg.CORS.AllowedOrigins[1])
	assert.Equal(t, 200, cfg.Transport.MaxIdleConns)
	assert.Equal(t, 20, cfg.Transport.MaxIdleConnsPerHost)
	assert.Equal(t, "120s", cfg.Transport.IdleConnTimeout)
}

func TestParseTransportAndCircuitBreakerConfig(t *testing.T) {
	data := []byte(`
upstream: http://localhost:8080
transport:
  request_timeout: "30s"
  sse_idle_timeout: "10m"
circuit_breaker:
  max_failures: 5
  timeout: "60s"
`)
	cfg, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, "30s", cfg.Transport.RequestTimeout)
	assert.Equal(t, "10m", cfg.Transport.SSEIdleTimeout)
	assert.Equal(t, 5, cfg.CircuitBreaker.MaxFailures)
	assert.Equal(t, "60s", cfg.CircuitBreaker.Timeout)
}
