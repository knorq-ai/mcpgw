package intercept

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/policy"
	"github.com/stretchr/testify/assert"
)

func newResponseTestEngine(responsePatterns []string, allowedTools []string) *policy.Engine {
	return policy.NewEngine(&policy.PolicyFile{
		Version:          "v1",
		Mode:             "enforce",
		Rules:            []policy.Rule{{Name: "allow-all", Match: policy.Match{Methods: []string{"*"}}, Action: "allow"}},
		ResponsePatterns: responsePatterns,
		AllowedTools:     allowedTools,
	})
}

func TestResponseInterceptorPassClientToServer(t *testing.T) {
	engine := newResponseTestEngine([]string{`secret_key`}, nil)
	ri := NewResponseInterceptor(engine)

	// C→S 方向は常に通過
	result := ri.Intercept(context.Background(), DirClientToServer, nil, []byte(`{"secret_key":"abc"}`))
	assert.Equal(t, ActionPass, result.Action)
}

func TestResponseInterceptorPatternScan(t *testing.T) {
	engine := newResponseTestEngine([]string{`(?i)api[_-]?key\s*[:=]`, `(?i)password\s*[:=]`}, nil)
	ri := NewResponseInterceptor(engine)

	tests := []struct {
		name    string
		raw     string
		blocked bool
	}{
		{"contains api_key", `{"result":"api_key: sk-12345"}`, true},
		{"contains API-KEY", `{"result":"API-KEY = abc"}`, true},
		{"contains password", `{"result":"password: secret"}`, true},
		{"safe content", `{"result":"hello world"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ri.Intercept(context.Background(), DirServerToClient, nil, []byte(tt.raw))
			if tt.blocked {
				assert.Equal(t, ActionBlock, result.Action)
				assert.Contains(t, result.Reason, "forbidden pattern")
			} else {
				assert.Equal(t, ActionPass, result.Action)
			}
		})
	}
}

func TestResponseInterceptorToolsList(t *testing.T) {
	engine := newResponseTestEngine(nil, []string{"read_*", "write_*", "list_*"})
	ri := NewResponseInterceptor(engine)

	// tools/list レスポンスに許可されたツールのみ → 通過
	safeResult := json.RawMessage(`{"tools":[{"name":"read_file"},{"name":"write_file"}]}`)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  safeResult,
	}
	result := ri.Intercept(context.Background(), DirServerToClient, msg, []byte(`{}`))
	assert.Equal(t, ActionPass, result.Action)

	// 未許可ツール含む → ブロック
	unsafeResult := json.RawMessage(`{"tools":[{"name":"read_file"},{"name":"exec_command"}]}`)
	msg2 := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Result:  unsafeResult,
	}
	result = ri.Intercept(context.Background(), DirServerToClient, msg2, []byte(`{}`))
	assert.Equal(t, ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "exec_command")
}

func TestResponseInterceptorToolsListNoConfig(t *testing.T) {
	engine := newResponseTestEngine(nil, nil)
	ri := NewResponseInterceptor(engine)

	// allowed_tools 未設定 → 常に通過
	toolsResult := json.RawMessage(`{"tools":[{"name":"anything"}]}`)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  toolsResult,
	}
	result := ri.Intercept(context.Background(), DirServerToClient, msg, []byte(`{}`))
	assert.Equal(t, ActionPass, result.Action)
}

func TestResponseInterceptorNilEngine(t *testing.T) {
	ri := &ResponseInterceptor{}
	result := ri.Intercept(context.Background(), DirServerToClient, nil, []byte(`secret`))
	assert.Equal(t, ActionPass, result.Action)
}

func TestCheckToolsList(t *testing.T) {
	tests := []struct {
		name         string
		result       json.RawMessage
		allowedTools []string
		want         string
	}{
		{"all allowed", json.RawMessage(`{"tools":[{"name":"read_file"}]}`), []string{"read_*"}, ""},
		{"unauthorized", json.RawMessage(`{"tools":[{"name":"exec_cmd"}]}`), []string{"read_*"}, "exec_cmd"},
		{"not tools/list", json.RawMessage(`{"value":42}`), []string{"read_*"}, ""},
		{"empty tools", json.RawMessage(`{"tools":[]}`), []string{"read_*"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, checkToolsList(tt.result, tt.allowedTools))
		})
	}
}
