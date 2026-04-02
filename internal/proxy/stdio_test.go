package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passAll は全メッセージを通過させる interceptor。
type passAll struct{}

func (p *passAll) Intercept(_ context.Context, _ intercept.Direction, _ *jsonrpc.Message, _ []byte) intercept.Result {
	return intercept.Result{Action: intercept.ActionPass}
}

// blockMethod は指定メソッドをブロックする interceptor。
type blockMethod struct {
	method string
}

func (b *blockMethod) Intercept(_ context.Context, _ intercept.Direction, msg *jsonrpc.Message, _ []byte) intercept.Result {
	if msg != nil && msg.Method == b.method {
		return intercept.Result{Action: intercept.ActionBlock, Reason: "blocked: " + b.method}
	}
	return intercept.Result{Action: intercept.ActionPass}
}

func TestStdioProxyCatEcho(t *testing.T) {
	chain := intercept.NewChain(&passAll{})
	proxy := NewStdioProxy("cat", nil, chain, nil)

	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	clientIn := strings.NewReader(input)
	var clientOut bytes.Buffer

	err := proxy.Run(context.Background(), clientIn, &clientOut)
	require.NoError(t, err)

	// cat がそのままエコーするため、同じメッセージが返るはず
	var msg jsonrpc.Message
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(clientOut.Bytes()), &msg))
	assert.Equal(t, "initialize", msg.Method)
	assert.Equal(t, "2.0", msg.JSONRPC)
}

func TestStdioProxyMultipleMessages(t *testing.T) {
	chain := intercept.NewChain(&passAll{})
	proxy := NewStdioProxy("cat", nil, chain, nil)

	messages := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	}
	input := strings.Join(messages, "\n") + "\n"
	var clientOut bytes.Buffer

	err := proxy.Run(context.Background(), strings.NewReader(input), &clientOut)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(clientOut.String()), "\n")
	assert.Len(t, lines, 3)
}

func TestStdioProxyBlockedMessage(t *testing.T) {
	chain := intercept.NewChain(&blockMethod{method: "tools/call"})
	proxy := NewStdioProxy("cat", nil, chain, nil)

	messages := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`,
	}
	input := strings.Join(messages, "\n") + "\n"
	var clientOut bytes.Buffer

	err := proxy.Run(context.Background(), strings.NewReader(input), &clientOut)
	require.NoError(t, err)

	// 出力をパースして ID ごとに分類
	lines := strings.Split(strings.TrimSpace(clientOut.String()), "\n")
	require.Len(t, lines, 3)

	byID := map[string]*jsonrpc.Message{}
	for _, line := range lines {
		var msg jsonrpc.Message
		require.NoError(t, json.Unmarshal([]byte(line), &msg))
		id := string(msg.ID)
		byID[id] = &msg
	}

	// id=1 (initialize) は通過してエコーされるべき
	init := byID["1"]
	require.NotNil(t, init, "initialize (id=1) が出力に含まれるべき")
	assert.Equal(t, "initialize", init.Method)
	assert.Nil(t, init.Error)

	// id=2 (tools/call) はブロックされ、エラーレスポンスが返るべき
	blocked := byID["2"]
	require.NotNil(t, blocked, "tools/call (id=2) のエラーレスポンスが出力に含まれるべき")
	require.NotNil(t, blocked.Error)
	assert.Equal(t, -32600, blocked.Error.Code)
	assert.Contains(t, blocked.Error.Message, "blocked")

	// id=3 (tools/list) は通過してエコーされるべき
	list := byID["3"]
	require.NotNil(t, list, "tools/list (id=3) が出力に含まれるべき")
	assert.Equal(t, "tools/list", list.Method)
	assert.Nil(t, list.Error)
}

func TestStdioProxyPumpWriteError(t *testing.T) {
	chain := intercept.NewChain(&passAll{})
	proxy := NewStdioProxy("cat", nil, chain, nil)

	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"

	// 書き込み先を errWriter にして書き込みエラーを強制する
	err := proxy.Run(context.Background(), strings.NewReader(input), &errWriter{})
	// pump が書き込みエラーを返すことを確認
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write error")
}

// errWriter は常にエラーを返す io.Writer。
type errWriter struct{}

func (e *errWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

func TestBuildErrorResponse(t *testing.T) {
	resp := buildErrorResponse(json.RawMessage(`42`), -32600, "denied by policy")
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, json.RawMessage(`42`), resp.ID)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32600, resp.Error.Code)
	assert.Equal(t, "denied by policy", resp.Error.Message)
}
