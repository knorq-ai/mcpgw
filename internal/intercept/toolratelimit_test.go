package intercept

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/knorq-ai/mcpgw/internal/auth"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

func TestToolRateLimitInterceptorBasic(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	rl := newToolRateLimitInterceptor(1.0, 2, nowFn) // 1 req/sec, burst=2
	defer rl.Close()

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file"}`),
	}

	// バースト分（2回）は通過
	r := rl.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)

	r = rl.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)

	// 3回目はブロック
	r = rl.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, r.Action)
	assert.Contains(t, r.Reason, "read_file")
}

func TestToolRateLimitInterceptorPerToolIsolation(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	rl := newToolRateLimitInterceptor(1.0, 1, nowFn)
	defer rl.Close()

	readMsg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file"}`),
	}
	writeMsg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"write_file"}`),
	}

	// read_file 1回 → 通過
	r := rl.Intercept(context.Background(), DirClientToServer, readMsg, nil)
	assert.Equal(t, ActionPass, r.Action)

	// write_file 1回 → 通過（別バケット）
	r = rl.Intercept(context.Background(), DirClientToServer, writeMsg, nil)
	assert.Equal(t, ActionPass, r.Action)

	// read_file 2回目 → ブロック
	r = rl.Intercept(context.Background(), DirClientToServer, readMsg, nil)
	assert.Equal(t, ActionBlock, r.Action)
}

func TestToolRateLimitInterceptorPerSubject(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	rl := newToolRateLimitInterceptor(1.0, 1, nowFn)
	defer rl.Close()

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file"}`),
	}

	ctx1 := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "user-a"})
	ctx2 := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "user-b"})

	// user-a 1回 → 通過
	r := rl.Intercept(ctx1, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)

	// user-b 1回 → 通過（別バケット）
	r = rl.Intercept(ctx2, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)

	// user-a 2回目 → ブロック
	r = rl.Intercept(ctx1, DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, r.Action)
}

func TestToolRateLimitInterceptorServerToClient(t *testing.T) {
	rl := newToolRateLimitInterceptor(0.001, 1, time.Now)
	defer rl.Close()

	// S→C 方向は常に通過
	r := rl.Intercept(context.Background(), DirServerToClient, nil, nil)
	assert.Equal(t, ActionPass, r.Action)
}

func TestToolRateLimitInterceptorNonToolsCall(t *testing.T) {
	rl := newToolRateLimitInterceptor(0.001, 1, time.Now)
	defer rl.Close()

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/list",
	}

	// tools/call 以外は通過
	r := rl.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)
}

func TestToolRateLimitInterceptorRefill(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	rl := newToolRateLimitInterceptor(1.0, 1, nowFn)
	defer rl.Close()

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_file"}`),
	}

	// 1回目 → 通過
	r := rl.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)

	// 2回目 → ブロック
	r = rl.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, r.Action)

	// 1秒経過 → トークン補充 → 通過
	now = now.Add(1 * time.Second)
	r = rl.Intercept(context.Background(), DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)
}
