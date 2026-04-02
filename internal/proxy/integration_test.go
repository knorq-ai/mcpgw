package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// エンドツーエンドテスト: cat を子プロセスとして使い、
// 監査ログ付きでメッセージが往復することを確認する。
func TestIntegrationCatWithAudit(t *testing.T) {
	// 監査ログの準備
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewLogger(logPath, audit.DefaultMaxSize)
	require.NoError(t, err)
	defer logger.Close()

	// interceptor チェーン（空）+ 監査ロガー
	chain := intercept.NewChain()
	auditLogger := intercept.NewAuditLogger(logger)

	// テスト入力: MCP initialize フロー
	messages := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	}
	input := strings.Join(messages, "\n") + "\n"

	proxy := NewStdioProxy("cat", nil, chain, auditLogger)
	var clientOut bytes.Buffer
	err = proxy.Run(context.Background(), strings.NewReader(input), &clientOut)
	require.NoError(t, err)

	// 出力の検証: cat がエコーするため3行返るはず
	outLines := strings.Split(strings.TrimSpace(clientOut.String()), "\n")
	require.Len(t, outLines, 3)

	// 各メッセージが正しくパースできることを確認
	for i, line := range outLines {
		var msg jsonrpc.Message
		require.NoError(t, json.Unmarshal([]byte(line), &msg), "line %d", i)
		assert.Equal(t, "2.0", msg.JSONRPC)
	}

	// 監査ログの検証
	logger.Close() // flush
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)

	logLines := strings.Split(strings.TrimSpace(string(logData)), "\n")
	// C→S: 3メッセージ + S→C: 3メッセージ(cat エコー) = 6エントリ
	require.Len(t, logLines, 6, "監査ログに6エントリ記録されるべき")

	// 最初のエントリを検証
	var entry audit.Entry
	require.NoError(t, json.Unmarshal([]byte(logLines[0]), &entry))
	assert.Equal(t, "c2s", entry.Direction)
	assert.Equal(t, "initialize", entry.Method)
	assert.Equal(t, "request", entry.Kind)
	assert.Equal(t, "pass", entry.Action)
}

// testdata のフィクスチャを使ったテスト
func TestIntegrationWithFixtures(t *testing.T) {
	fixtures := []string{
		"../../testdata/messages/initialize_request.json",
		"../../testdata/messages/tools_call_request.json",
	}

	var inputLines []string
	for _, f := range fixtures {
		data, err := os.ReadFile(f)
		require.NoError(t, err)
		inputLines = append(inputLines, strings.TrimSpace(string(data)))
	}

	chain := intercept.NewChain(&passAll{})
	proxy := NewStdioProxy("cat", nil, chain, nil)

	input := strings.Join(inputLines, "\n") + "\n"
	var clientOut bytes.Buffer
	err := proxy.Run(context.Background(), strings.NewReader(input), &clientOut)
	require.NoError(t, err)

	outLines := strings.Split(strings.TrimSpace(clientOut.String()), "\n")
	assert.Len(t, outLines, len(fixtures))
}
