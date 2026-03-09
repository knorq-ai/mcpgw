package schema

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Name(t *testing.T) {
	assert.Equal(t, "schema", New().Name())
}

func TestPlugin_Init(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))
	assert.NotNil(t, p.cache)
	assert.False(t, p.strict)
}

func TestPlugin_Init_Strict(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{"strict": true}))
	assert.True(t, p.strict)
}

func TestPlugin_CacheFromToolsList(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	// tools/list レスポンスをシミュレート
	result, _ := json.Marshal(map[string]any{
		"tools": []map[string]any{
			{
				"name": "read_file",
				"inputSchema": map[string]any{
					"type":     "object",
					"required": []string{"path"},
					"properties": map[string]any{
						"path": map[string]any{"type": "string"},
					},
				},
			},
		},
	})

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  result,
	}

	r := p.Intercept(context.Background(), intercept.DirServerToClient, msg, nil)
	assert.Equal(t, intercept.ActionPass, r.Action)
	assert.Equal(t, 1, p.cache.Count())

	// スキーマがキャッシュされていることを確認
	_, ok := p.cache.Get("read_file")
	assert.True(t, ok)
}

func TestPlugin_ValidateToolCall_Pass(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	// スキーマをキャッシュ
	p.cache.Set("read_file", json.RawMessage(`{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}`))

	// 正しい引数で tools/call
	params, _ := json.Marshal(map[string]any{
		"name":      "read_file",
		"arguments": map[string]any{"path": "/etc/passwd"},
	})
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  params,
	}

	r := p.Intercept(context.Background(), intercept.DirClientToServer, msg, nil)
	assert.Equal(t, intercept.ActionPass, r.Action)
}

func TestPlugin_ValidateToolCall_MissingRequired(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	// スキーマをキャッシュ
	p.cache.Set("read_file", json.RawMessage(`{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}`))

	// required フィールドが欠けている
	params, _ := json.Marshal(map[string]any{
		"name":      "read_file",
		"arguments": map[string]any{"encoding": "utf-8"},
	})
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  params,
	}

	r := p.Intercept(context.Background(), intercept.DirClientToServer, msg, nil)
	assert.Equal(t, intercept.ActionBlock, r.Action)
	assert.Equal(t, "schema_violation", r.ThreatType)
	assert.Contains(t, r.Reason, "path")
}

func TestPlugin_ValidateToolCall_UnknownProperty_Strict(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{"strict": true}))

	p.cache.Set("read_file", json.RawMessage(`{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}`))

	// unknown property を含む
	params, _ := json.Marshal(map[string]any{
		"name":      "read_file",
		"arguments": map[string]any{"path": "/etc/passwd", "unknown_field": "value"},
	})
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  params,
	}

	r := p.Intercept(context.Background(), intercept.DirClientToServer, msg, nil)
	assert.Equal(t, intercept.ActionBlock, r.Action)
	assert.Contains(t, r.Reason, "unknown_field")
}

func TestPlugin_ValidateToolCall_NoSchema_Pass(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	// スキーマ未キャッシュ → fail-open
	params, _ := json.Marshal(map[string]any{
		"name":      "unknown_tool",
		"arguments": map[string]any{"anything": "goes"},
	})
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  params,
	}

	r := p.Intercept(context.Background(), intercept.DirClientToServer, msg, nil)
	assert.Equal(t, intercept.ActionPass, r.Action)
}

func TestPlugin_NonToolsCall_Pass(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		Method:  "tools/list",
	}

	r := p.Intercept(context.Background(), intercept.DirClientToServer, msg, nil)
	assert.Equal(t, intercept.ActionPass, r.Action)
}

func TestPlugin_NilMessage_Pass(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	r := p.Intercept(context.Background(), intercept.DirClientToServer, nil, nil)
	assert.Equal(t, intercept.ActionPass, r.Action)
}

func TestSchemaCache(t *testing.T) {
	c := NewSchemaCache()
	assert.Equal(t, 0, c.Count())

	c.Set("tool1", json.RawMessage(`{"type":"object"}`))
	assert.Equal(t, 1, c.Count())

	s, ok := c.Get("tool1")
	assert.True(t, ok)
	assert.Equal(t, `{"type":"object"}`, string(s))

	_, ok = c.Get("nonexistent")
	assert.False(t, ok)
}

func TestPlugin_ValidateToolCall_TypeMismatch_String(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	// integer を期待するフィールドに string を渡す → ブロック
	p.cache.Set("get_user", json.RawMessage(`{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"integer"}}}`))

	params, _ := json.Marshal(map[string]any{
		"name":      "get_user",
		"arguments": map[string]any{"user_id": "../../etc/passwd"},
	})
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  params,
	}

	r := p.Intercept(context.Background(), intercept.DirClientToServer, msg, nil)
	assert.Equal(t, intercept.ActionBlock, r.Action)
	assert.Contains(t, r.Reason, "user_id")
	assert.Contains(t, r.Reason, "expected integer")
}

func TestPlugin_ValidateToolCall_TypeMismatch_Number(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	// string を期待するフィールドに number を渡す → ブロック
	p.cache.Set("greet", json.RawMessage(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`))

	params, _ := json.Marshal(map[string]any{
		"name":      "greet",
		"arguments": map[string]any{"name": 12345},
	})
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  params,
	}

	r := p.Intercept(context.Background(), intercept.DirClientToServer, msg, nil)
	assert.Equal(t, intercept.ActionBlock, r.Action)
	assert.Contains(t, r.Reason, "name")
	assert.Contains(t, r.Reason, "expected string")
}

func TestPlugin_ValidateToolCall_TypeMatch(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	// 全プロパティに正しい型を渡す → 通過
	p.cache.Set("multi_type", json.RawMessage(`{
		"type":"object",
		"required":["s","n","i","b","a","o"],
		"properties":{
			"s":{"type":"string"},
			"n":{"type":"number"},
			"i":{"type":"integer"},
			"b":{"type":"boolean"},
			"a":{"type":"array"},
			"o":{"type":"object"}
		}
	}`))

	params, _ := json.Marshal(map[string]any{
		"name": "multi_type",
		"arguments": map[string]any{
			"s": "hello",
			"n": 3.14,
			"i": 42,
			"b": true,
			"a": []any{1, 2, 3},
			"o": map[string]any{"key": "val"},
		},
	})
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  params,
	}

	r := p.Intercept(context.Background(), intercept.DirClientToServer, msg, nil)
	assert.Equal(t, intercept.ActionPass, r.Action)
}

func TestPlugin_Close(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))
	assert.NoError(t, p.Close())
}
