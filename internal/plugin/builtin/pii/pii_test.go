package pii

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
	p := New()
	assert.Equal(t, "pii", p.Name())
}

func TestPlugin_Init_Defaults(t *testing.T) {
	p := New()
	err := p.Init(map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, ModeDetect, p.mode)
	assert.Equal(t, len(allPatterns), len(p.patterns))
}

func TestPlugin_Init_Redact(t *testing.T) {
	p := New()
	err := p.Init(map[string]any{"mode": "redact"})
	require.NoError(t, err)
	assert.Equal(t, ModeRedact, p.mode)
}

func TestPlugin_Init_UnknownMode(t *testing.T) {
	p := New()
	err := p.Init(map[string]any{"mode": "unknown"})
	assert.Error(t, err)
}

func TestPlugin_Init_SelectPatterns(t *testing.T) {
	p := New()
	err := p.Init(map[string]any{
		"patterns": []any{"email", "ssn"},
	})
	require.NoError(t, err)
	assert.Len(t, p.patterns, 2)
}

func TestPlugin_Init_UnknownPattern(t *testing.T) {
	p := New()
	err := p.Init(map[string]any{
		"patterns": []any{"nonexistent"},
	})
	assert.Error(t, err)
}

func TestPlugin_Init_ExcludeTools(t *testing.T) {
	p := New()
	err := p.Init(map[string]any{
		"exclude_tools": []any{"debug_tool"},
	})
	require.NoError(t, err)
	assert.True(t, p.excludeTools["debug_tool"])
}

func newToolCallMsg(toolName string, args map[string]any) (*jsonrpc.Message, []byte) {
	params := map[string]any{
		"name":      toolName,
		"arguments": args,
	}
	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  params,
	})
	paramsRaw, _ := json.Marshal(params)
	return &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  paramsRaw,
	}, raw
}

func newResponseMsg(result map[string]any) (*jsonrpc.Message, []byte) {
	resultRaw, _ := json.Marshal(result)
	raw, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  result,
	})
	return &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  resultRaw,
	}, raw
}

func TestPlugin_Detect_CreditCard(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"mode":     "detect",
		"patterns": []any{"credit_card"},
	}))

	msg, raw := newToolCallMsg("send_payment", map[string]any{
		"card": "4111-1111-1111-1111",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, intercept.ActionPass, result.Action) // detect モード → pass
	assert.Equal(t, "pii_detected", result.ThreatType)
	assert.InDelta(t, 0.95, result.ThreatScore, 0.01)
}

func TestPlugin_Redact_CreditCard(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"mode":     "redact",
		"patterns": []any{"credit_card"},
	}))

	msg, raw := newToolCallMsg("send_payment", map[string]any{
		"card": "4111-1111-1111-1111",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, intercept.ActionRedact, result.Action)
	assert.Contains(t, result.Reason, "credit_card")
	assert.Equal(t, "pii_detected", result.ThreatType)
	// RedactedBody にリダクション済みメッセージが含まれることを検証
	require.NotNil(t, result.RedactedBody)
	assert.Contains(t, string(result.RedactedBody), "[REDACTED:credit_card]")
	assert.NotContains(t, string(result.RedactedBody), "4111-1111-1111-1111")
}

func TestPlugin_Detect_SSN(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"patterns": []any{"ssn"},
	}))

	msg, raw := newToolCallMsg("submit_form", map[string]any{
		"ssn": "123-45-6789",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, "pii_detected", result.ThreatType)
}

func TestPlugin_Detect_InvalidSSN(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"patterns": []any{"ssn"},
	}))

	// 000 で始まる SSN は無効
	msg, raw := newToolCallMsg("submit_form", map[string]any{
		"ssn": "000-12-3456",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, intercept.ActionPass, result.Action)
	assert.Empty(t, result.ThreatType) // 検出されない
}

func TestPlugin_Detect_Email(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"patterns": []any{"email"},
	}))

	msg, raw := newToolCallMsg("send_email", map[string]any{
		"to": "user@example.com",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, "pii_detected", result.ThreatType)
	assert.InDelta(t, 0.5, result.ThreatScore, 0.01)
}

func TestPlugin_Detect_Phone(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"patterns": []any{"phone"},
	}))

	msg, raw := newToolCallMsg("contact", map[string]any{
		"phone": "(555) 123-4567",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, "pii_detected", result.ThreatType)
}

func TestPlugin_Detect_AWSKey(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"patterns": []any{"aws_key"},
	}))

	msg, raw := newToolCallMsg("deploy", map[string]any{
		"key": "AKIAIOSFODNN7EXAMPLE",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, "pii_detected", result.ThreatType)
	assert.InDelta(t, 0.9, result.ThreatScore, 0.01)
}

func TestPlugin_Detect_NoMatch(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	msg, raw := newToolCallMsg("hello", map[string]any{
		"message": "Hello, world!",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, intercept.ActionPass, result.Action)
	assert.Empty(t, result.ThreatType)
}

func TestPlugin_Redact_Response(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"mode":     "redact",
		"patterns": []any{"ssn"},
	}))

	msg, raw := newResponseMsg(map[string]any{
		"data": "The SSN is 123-45-6789",
	})

	result := p.Intercept(context.Background(), intercept.DirServerToClient, msg, raw)
	assert.Equal(t, intercept.ActionRedact, result.Action)
	assert.Equal(t, "pii_detected", result.ThreatType)
	require.NotNil(t, result.RedactedBody)
	assert.Contains(t, string(result.RedactedBody), "[REDACTED:ssn]")
	assert.NotContains(t, string(result.RedactedBody), "123-45-6789")
}

func TestPlugin_ExcludeTool(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"mode":          "redact",
		"patterns":      []any{"email"},
		"exclude_tools": []any{"debug_tool"},
	}))

	msg, raw := newToolCallMsg("debug_tool", map[string]any{
		"email": "user@example.com",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, intercept.ActionPass, result.Action)
}

func TestPlugin_NilMessage(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))

	result := p.Intercept(context.Background(), intercept.DirClientToServer, nil, []byte("{}"))
	assert.Equal(t, intercept.ActionPass, result.Action)
}

func TestPlugin_Detect_InvalidCreditCard_Luhn(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"patterns": []any{"credit_card"},
	}))

	// Luhn チェックを通過しない番号
	msg, raw := newToolCallMsg("pay", map[string]any{
		"card": "4111-1111-1111-1112",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, intercept.ActionPass, result.Action)
	assert.Empty(t, result.ThreatType)
}

func TestPlugin_Redact_MultiplePatterns(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{
		"mode":     "redact",
		"patterns": []any{"email", "ssn"},
	}))

	msg, raw := newToolCallMsg("submit", map[string]any{
		"data": "SSN: 123-45-6789, email: user@example.com",
	})

	result := p.Intercept(context.Background(), intercept.DirClientToServer, msg, raw)
	assert.Equal(t, intercept.ActionRedact, result.Action)
	assert.Equal(t, "pii_detected", result.ThreatType)
	assert.Contains(t, result.ThreatDetails["patterns"], "email")
	assert.Contains(t, result.ThreatDetails["patterns"], "ssn")
	require.NotNil(t, result.RedactedBody)
	assert.Contains(t, string(result.RedactedBody), "[REDACTED:ssn]")
	assert.Contains(t, string(result.RedactedBody), "[REDACTED:email]")
	assert.NotContains(t, string(result.RedactedBody), "123-45-6789")
	assert.NotContains(t, string(result.RedactedBody), "user@example.com")
}

func TestPlugin_Close(t *testing.T) {
	p := New()
	require.NoError(t, p.Init(map[string]any{}))
	assert.NoError(t, p.Close())
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"4111111111111111", true},
		{"4111-1111-1111-1111", true},
		{"5500 0000 0000 0004", true},
		{"378282246310005", true},  // Amex
		{"6011111111111117", true}, // Discover
		{"1234567890123456", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, luhnCheck(tt.input))
		})
	}
}

func TestValidateSSN(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123-45-6789", true},
		{"000-12-3456", false}, // 000 は無効
		{"666-12-3456", false}, // 666 は無効
		{"900-12-3456", false}, // 900+ は無効
		{"123-00-6789", false}, // group 00 は無効
		{"123-45-0000", false}, // serial 0000 は無効
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, validateSSN(tt.input))
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	// 低エントロピー
	lowEntropy := shannonEntropy("aaaaaaaaaa")
	assert.Less(t, lowEntropy, 1.0)

	// 高エントロピー
	highEntropy := shannonEntropy("aB3xK9mQ7pZ2wL5nR8vJ4cY6fH1dG0e")
	assert.Greater(t, highEntropy, 3.5)
}
