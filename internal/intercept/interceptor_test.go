package intercept

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

type passInterceptor struct{ called bool }

func (p *passInterceptor) Intercept(_ context.Context, _ Direction, _ *jsonrpc.Message, _ []byte) Result {
	p.called = true
	return Result{Action: ActionPass}
}

type blockInterceptor struct{ called bool }

func (b *blockInterceptor) Intercept(_ context.Context, _ Direction, _ *jsonrpc.Message, _ []byte) Result {
	b.called = true
	return Result{Action: ActionBlock, Reason: "blocked by test"}
}

func TestChainAllPass(t *testing.T) {
	p1 := &passInterceptor{}
	p2 := &passInterceptor{}
	chain := NewChain(p1, p2)

	msg := &jsonrpc.Message{JSONRPC: "2.0", Method: "test"}
	result := chain.Process(context.Background(), DirClientToServer, msg, nil)

	assert.Equal(t, ActionPass, result.Action)
	assert.True(t, p1.called)
	assert.True(t, p2.called)
}

func TestChainShortCircuit(t *testing.T) {
	p1 := &passInterceptor{}
	b := &blockInterceptor{}
	p2 := &passInterceptor{}
	chain := NewChain(p1, b, p2)

	msg := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call"}
	result := chain.Process(context.Background(), DirClientToServer, msg, nil)

	assert.Equal(t, ActionBlock, result.Action)
	assert.Equal(t, "blocked by test", result.Reason)
	assert.True(t, p1.called)
	assert.True(t, b.called)
	assert.False(t, p2.called) // 短絡によりスキップ
}

func TestChainEmpty(t *testing.T) {
	chain := NewChain()
	result := chain.Process(context.Background(), DirClientToServer, nil, nil)
	assert.Equal(t, ActionPass, result.Action)
}

func TestDirectionString(t *testing.T) {
	assert.Equal(t, "c2s", DirClientToServer.String())
	assert.Equal(t, "s2c", DirServerToClient.String())
}
