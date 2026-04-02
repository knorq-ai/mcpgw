package intercept

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/knorq-ai/mcpgw/internal/auth"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/policy"
	"github.com/stretchr/testify/assert"
)

func newEnforceEngine() *policy.Engine {
	return policy.NewEngine(&policy.PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []policy.Rule{
			{Name: "deny-exec", Match: policy.Match{
				Methods: []string{"tools/call"},
				Tools:   []string{"exec_*"},
			}, Action: "deny"},
			{Name: "allow-all", Match: policy.Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})
}

func newAuditEngine() *policy.Engine {
	return policy.NewEngine(&policy.PolicyFile{
		Version: "v1",
		Mode:    "audit",
		Rules: []policy.Rule{
			{Name: "deny-all", Match: policy.Match{Methods: []string{"*"}}, Action: "deny"},
		},
	})
}

func TestPolicyInterceptorBlocksDeniedTool(t *testing.T) {
	pi := NewPolicyInterceptor(newEnforceEngine())
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"exec_cmd"}`),
	}
	result := pi.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "deny-exec")
}

func TestPolicyInterceptorAllowsPermittedTool(t *testing.T) {
	pi := NewPolicyInterceptor(newEnforceEngine())
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file"}`),
	}
	result := pi.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
}

func TestPolicyInterceptorPassesNilMessage(t *testing.T) {
	pi := NewPolicyInterceptor(newEnforceEngine())
	result := pi.Intercept(context.Background(), DirClientToServer, nil, nil)
	assert.Equal(t, ActionPass, result.Action)
}

func TestPolicyInterceptorPassesServerToClient(t *testing.T) {
	pi := NewPolicyInterceptor(newEnforceEngine())
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"exec_cmd"}`),
	}
	// S→C 方向は常に通過
	result := pi.Intercept(context.Background(), DirServerToClient, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
}

func TestPolicyInterceptorPassesResponse(t *testing.T) {
	pi := NewPolicyInterceptor(newEnforceEngine())
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  json.RawMessage(`{}`),
	}
	// Method 空 → 通過
	result := pi.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
}

func TestPolicyInterceptorAuditModeNeverBlocks(t *testing.T) {
	pi := NewPolicyInterceptor(newAuditEngine())
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"exec_cmd"}`),
	}
	// audit モードでは deny 判定でもブロックしない
	result := pi.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, result.Action)
}

func TestPolicyInterceptorSwapEngine(t *testing.T) {
	// 初期エンジン: exec_cmd をブロック
	pi := NewPolicyInterceptor(newEnforceEngine())
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"exec_cmd"}`),
	}
	result := pi.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, result.Action, "SwapEngine 前はブロックされるべき")

	// 全許可エンジンに入れ替え
	allowAll := policy.NewEngine(&policy.PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []policy.Rule{
			{Name: "allow-all", Match: policy.Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})
	pi.SwapEngine(allowAll)

	result = pi.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, result.Action, "SwapEngine 後は通過すべき")
}

func TestPolicyInterceptorSwapEngineConcurrent(t *testing.T) {
	pi := NewPolicyInterceptor(newEnforceEngine())
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"exec_cmd"}`),
	}

	denyEngine := newEnforceEngine()
	allowEngine := policy.NewEngine(&policy.PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []policy.Rule{
			{Name: "allow-all", Match: policy.Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})

	// 複数の goroutine から同時に SwapEngine と Intercept を呼び出し、
	// -race でデータ競合がないことを検証する。
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			if i%2 == 0 {
				pi.SwapEngine(allowEngine)
			} else {
				pi.SwapEngine(denyEngine)
			}
		}
	}()
	for i := 0; i < 1000; i++ {
		result := pi.Intercept(context.Background(), DirClientToServer, msg, nil)
		// どちらのエンジンでも結果は ActionPass か ActionBlock のどちらか
		assert.True(t, result.Action == ActionPass || result.Action == ActionBlock)
	}
	<-done
}

func TestPolicyInterceptorWithIdentity(t *testing.T) {
	engine := policy.NewEngine(&policy.PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []policy.Rule{
			{Name: "admin-exec", Match: policy.Match{
				Methods:  []string{"tools/call"},
				Tools:    []string{"exec_*"},
				Subjects: []string{"admin-*"},
			}, Action: "allow"},
			{Name: "deny-exec", Match: policy.Match{
				Methods: []string{"tools/call"},
				Tools:   []string{"exec_*"},
			}, Action: "deny"},
			{Name: "allow-all", Match: policy.Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})
	pi := NewPolicyInterceptor(engine)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"exec_cmd"}`),
	}

	// admin Identity → 許可
	adminCtx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "admin-alice", Method: "jwt"})
	result := pi.Intercept(adminCtx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, result.Action)

	// user Identity → ブロック
	userCtx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "user-bob", Method: "jwt"})
	result = pi.Intercept(userCtx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, result.Action)

	// 未認証 → subjects ルールにマッチしない → deny-exec → ブロック
	result = pi.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, result.Action)
}
