package intercept

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/knorq-ai/mcpgw/internal/config"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/metrics"
	"github.com/knorq-ai/mcpgw/internal/servereval"
	"github.com/stretchr/testify/assert"
)

func init() {
	metrics.Register()
}

func toolsListResponse(tools ...string) *jsonrpc.Message {
	type tool struct {
		Name string `json:"name"`
	}
	var tl []tool
	for _, name := range tools {
		tl = append(tl, tool{Name: name})
	}
	result, _ := json.Marshal(map[string]any{"tools": tl})
	return &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  result,
	}
}

func TestServerEvalLowRiskAutoApprove(t *testing.T) {
	store := servereval.NewStore()
	cfg := config.ServerEvalConfig{
		Enabled: true,
		Mode:    "enforce",
		AutoApprove: config.AutoApproveConfig{
			RiskLevels: []string{"low"},
		},
	}
	sei := NewServerEvalInterceptor(store, cfg, nil)

	ctx := WithUpstream(context.Background(), "http://safe-server")
	msg := toolsListResponse("echo", "get_weather")
	result := sei.Intercept(ctx, DirServerToClient, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
	assert.Equal(t, "approved", store.Get("http://safe-server").Status)
}

func TestServerEvalHighRiskEnforceBlock(t *testing.T) {
	store := servereval.NewStore()
	cfg := config.ServerEvalConfig{
		Enabled: true,
		Mode:    "enforce",
	}
	sei := NewServerEvalInterceptor(store, cfg, nil)

	ctx := WithUpstream(context.Background(), "http://risky-server")
	msg := toolsListResponse("exec_cmd", "delete_all")
	result := sei.Intercept(ctx, DirServerToClient, msg, nil)
	assert.Equal(t, ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "pending evaluation")
}

func TestServerEvalHighRiskAuditPass(t *testing.T) {
	store := servereval.NewStore()
	cfg := config.ServerEvalConfig{
		Enabled: true,
		Mode:    "audit",
	}
	sei := NewServerEvalInterceptor(store, cfg, nil)

	ctx := WithUpstream(context.Background(), "http://risky-server")
	msg := toolsListResponse("exec_cmd")
	result := sei.Intercept(ctx, DirServerToClient, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
	assert.Equal(t, "pending", store.Get("http://risky-server").Status)
}

func TestServerEvalAllowlistMatch(t *testing.T) {
	store := servereval.NewStore()
	cfg := config.ServerEvalConfig{
		Enabled: true,
		Mode:    "enforce",
		Allowlist: []config.ServerEntry{
			{Upstream: "http://trusted*", Status: "approved"},
		},
	}
	sei := NewServerEvalInterceptor(store, cfg, nil)

	ctx := WithUpstream(context.Background(), "http://trusted-server")
	msg := toolsListResponse("exec_cmd")
	result := sei.Intercept(ctx, DirServerToClient, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
	assert.Equal(t, "approved", store.Get("http://trusted-server").Status)
}

func TestServerEvalCachedResult(t *testing.T) {
	store := servereval.NewStore()
	store.Set(&servereval.ServerInfo{Upstream: "http://cached", Status: "approved", RiskLevel: "low"})
	cfg := config.ServerEvalConfig{Enabled: true, Mode: "enforce"}
	sei := NewServerEvalInterceptor(store, cfg, nil)

	ctx := WithUpstream(context.Background(), "http://cached")
	msg := toolsListResponse("exec_cmd")
	result := sei.Intercept(ctx, DirServerToClient, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
}

func TestServerEvalNonToolsListPass(t *testing.T) {
	store := servereval.NewStore()
	cfg := config.ServerEvalConfig{Enabled: true, Mode: "enforce"}
	sei := NewServerEvalInterceptor(store, cfg, nil)

	ctx := WithUpstream(context.Background(), "http://any")
	// initialize レスポンス（tools フィールドなし）
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  json.RawMessage(`{"capabilities":{}}`),
	}
	result := sei.Intercept(ctx, DirServerToClient, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
}

func TestServerEvalC2SSkip(t *testing.T) {
	store := servereval.NewStore()
	cfg := config.ServerEvalConfig{Enabled: true, Mode: "enforce"}
	sei := NewServerEvalInterceptor(store, cfg, nil)

	result := sei.Intercept(context.Background(), DirClientToServer, nil, nil)
	assert.Equal(t, ActionPass, result.Action)
}
