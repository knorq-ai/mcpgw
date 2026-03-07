package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/policy"
)

func TestPolicyBlocksToolsCall(t *testing.T) {
	// ポリシー読み込み
	pf, err := policy.Load("../../testdata/policy_deny_tools.yaml")
	require.NoError(t, err)

	engine := policy.NewEngine(pf)
	policyInt := intercept.NewPolicyInterceptor(engine)
	chain := intercept.NewChain(policyInt)

	messages := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_cmd","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`,
	}
	input := strings.Join(messages, "\n") + "\n"

	proxy := NewStdioProxy("cat", nil, chain, nil)
	var clientOut bytes.Buffer
	err = proxy.Run(context.Background(), strings.NewReader(input), &clientOut)
	require.NoError(t, err)

	// 出力をパース
	lines := strings.Split(strings.TrimSpace(clientOut.String()), "\n")
	byID := map[string]*jsonrpc.Message{}
	for _, line := range lines {
		var msg jsonrpc.Message
		require.NoError(t, json.Unmarshal([]byte(line), &msg))
		byID[string(msg.ID)] = &msg
	}

	// id=1: initialize → 許可（エコー）
	assert.NotNil(t, byID["1"])
	assert.Equal(t, "initialize", byID["1"].Method)
	assert.Nil(t, byID["1"].Error)

	// id=2: exec_cmd → ブロック（エラーレスポンス）
	require.NotNil(t, byID["2"])
	require.NotNil(t, byID["2"].Error)
	assert.Equal(t, -32600, byID["2"].Error.Code)
	assert.Contains(t, byID["2"].Error.Message, "deny-exec")

	// id=3: read_file → 許可（ツールパターンにマッチしない）
	assert.NotNil(t, byID["3"])
	assert.Equal(t, "tools/call", byID["3"].Method)
	assert.Nil(t, byID["3"].Error)

	// id=4: tools/list → 許可
	assert.NotNil(t, byID["4"])
	assert.Equal(t, "tools/list", byID["4"].Method)
	assert.Nil(t, byID["4"].Error)
}

func TestPolicyAuditModeDoesNotBlock(t *testing.T) {
	pf := &policy.PolicyFile{
		Version: "v1",
		Mode:    "audit",
		Rules: []policy.Rule{
			{Name: "deny-all", Match: policy.Match{Methods: []string{"*"}}, Action: "deny"},
		},
	}
	engine := policy.NewEngine(pf)
	policyInt := intercept.NewPolicyInterceptor(engine)
	chain := intercept.NewChain(policyInt)

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec"}}` + "\n"

	proxy := NewStdioProxy("cat", nil, chain, nil)
	var clientOut bytes.Buffer
	err := proxy.Run(context.Background(), strings.NewReader(input), &clientOut)
	require.NoError(t, err)

	// audit モードではブロックしない — メッセージが通過する
	lines := strings.Split(strings.TrimSpace(clientOut.String()), "\n")
	require.Len(t, lines, 1)

	var msg jsonrpc.Message
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &msg))
	assert.Equal(t, "tools/call", msg.Method)
	assert.Nil(t, msg.Error)
}

func TestPolicyWithAuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewLogger(logPath, audit.DefaultMaxSize)
	require.NoError(t, err)
	defer logger.Close()

	pf, err := policy.Load("../../testdata/policy_deny_tools.yaml")
	require.NoError(t, err)

	engine := policy.NewEngine(pf)
	policyInt := intercept.NewPolicyInterceptor(engine)
	chain := intercept.NewChain(policyInt)
	auditLogger := intercept.NewAuditLogger(logger)

	messages := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_cmd"}}`,
	}
	input := strings.Join(messages, "\n") + "\n"

	proxy := NewStdioProxy("cat", nil, chain, auditLogger)
	var clientOut bytes.Buffer
	err = proxy.Run(context.Background(), strings.NewReader(input), &clientOut)
	require.NoError(t, err)

	// 監査ログを検証
	logger.Close()
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)

	logLines := strings.Split(strings.TrimSpace(string(logData)), "\n")

	// ブロックされたメッセージの監査ログエントリを探す
	foundBlock := false
	foundPass := false
	for _, line := range logLines {
		var entry audit.Entry
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		if entry.Method == "tools/call" && entry.Direction == "c2s" {
			assert.Equal(t, "block", entry.Action)
			assert.Contains(t, entry.Reason, "deny-exec")
			foundBlock = true
		}
		if entry.Method == "initialize" && entry.Direction == "c2s" {
			assert.Equal(t, "pass", entry.Action)
			foundPass = true
		}
	}
	assert.True(t, foundBlock, "ブロックされたメッセージの監査エントリが存在すべき")
	assert.True(t, foundPass, "通過したメッセージの監査エントリが存在すべき")
}
