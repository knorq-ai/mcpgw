package intercept

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yuyamorita/mcpgw/internal/audit"
	"github.com/yuyamorita/mcpgw/internal/jsonrpc"
)

func newTestAuditLogger(t *testing.T) (*AuditLogger, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewLogger(path, audit.DefaultMaxSize)
	require.NoError(t, err)
	t.Cleanup(func() { logger.Close() })
	return NewAuditLogger(logger), path
}

func readAuditEntries(t *testing.T, path string) []audit.Entry {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var entries []audit.Entry
	for _, line := range lines {
		if line == "" {
			continue
		}
		var e audit.Entry
		require.NoError(t, json.Unmarshal([]byte(line), &e))
		entries = append(entries, e)
	}
	return entries
}

func TestAuditLoggerPassMessage(t *testing.T) {
	al, path := newTestAuditLogger(t)

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/list",
	}
	al.Log(context.Background(), DirClientToServer, msg, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), Result{Action: ActionPass})

	entries := readAuditEntries(t, path)
	require.Len(t, entries, 1)
	assert.Equal(t, "c2s", entries[0].Direction)
	assert.Equal(t, "tools/list", entries[0].Method)
	assert.Equal(t, "1", entries[0].ID)
	assert.Equal(t, "request", entries[0].Kind)
	assert.Equal(t, "pass", entries[0].Action)
	assert.Equal(t, "", entries[0].Reason)
}

func TestAuditLoggerBlockMessage(t *testing.T) {
	al, path := newTestAuditLogger(t)

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"exec_cmd"}`),
	}
	result := Result{Action: ActionBlock, Reason: `denied by policy rule "deny-exec"`}
	al.Log(context.Background(), DirClientToServer, msg, []byte(`raw`), result)

	entries := readAuditEntries(t, path)
	require.Len(t, entries, 1)
	assert.Equal(t, "block", entries[0].Action)
	assert.Contains(t, entries[0].Reason, "deny-exec")
}

func TestAuditLoggerNilMessage(t *testing.T) {
	al, path := newTestAuditLogger(t)

	// msg が nil の場合（パース不能なメッセージ）
	al.Log(context.Background(), DirClientToServer, nil, []byte(`not json`), Result{Action: ActionPass})

	entries := readAuditEntries(t, path)
	require.Len(t, entries, 1)
	assert.Equal(t, "unknown", entries[0].Kind)
	assert.Equal(t, "", entries[0].Method)
}

func TestAuditLoggerServerToClient(t *testing.T) {
	al, path := newTestAuditLogger(t)

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  json.RawMessage(`{"tools":[]}`),
	}
	al.Log(context.Background(), DirServerToClient, msg, []byte(`raw`), Result{Action: ActionPass})

	entries := readAuditEntries(t, path)
	require.Len(t, entries, 1)
	assert.Equal(t, "s2c", entries[0].Direction)
	assert.Equal(t, "response", entries[0].Kind)
}

func TestAuditLoggerNotification(t *testing.T) {
	al, path := newTestAuditLogger(t)

	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	al.Log(context.Background(), DirClientToServer, msg, []byte(`raw`), Result{Action: ActionPass})

	entries := readAuditEntries(t, path)
	require.Len(t, entries, 1)
	assert.Equal(t, "notification", entries[0].Kind)
}

func TestAuditLoggerRecordsSize(t *testing.T) {
	al, path := newTestAuditLogger(t)

	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	msg := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize"}
	al.Log(context.Background(), DirClientToServer, msg, raw, Result{Action: ActionPass})

	entries := readAuditEntries(t, path)
	require.Len(t, entries, 1)
	assert.Equal(t, len(raw), entries[0].Size)
}

func TestAuditLoggerRecordsRequestID(t *testing.T) {
	al, path := newTestAuditLogger(t)

	ctx := WithRequestID(context.Background(), "test-req-id-123")
	msg := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/list"}
	al.Log(ctx, DirClientToServer, msg, []byte(`raw`), Result{Action: ActionPass})

	entries := readAuditEntries(t, path)
	require.Len(t, entries, 1)
	assert.Equal(t, "test-req-id-123", entries[0].RequestID)
}

func TestKindString(t *testing.T) {
	assert.Equal(t, "request", kindString(jsonrpc.KindRequest))
	assert.Equal(t, "response", kindString(jsonrpc.KindResponse))
	assert.Equal(t, "notification", kindString(jsonrpc.KindNotification))
	assert.Equal(t, "unknown", kindString(jsonrpc.KindUnknown))
}
