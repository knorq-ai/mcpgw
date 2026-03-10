package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/knorq-ai/mcpgw/internal/audit"
)

func writeTestAuditLog(t *testing.T, entries []audit.Entry) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, e := range entries {
		require.NoError(t, enc.Encode(e))
	}
	return path
}

func TestAnalyticsByTool(t *testing.T) {
	now := time.Now()
	path := writeTestAuditLog(t, []audit.Entry{
		{Timestamp: now, ToolName: "exec_cmd", Action: "block", Method: "tools/call"},
		{Timestamp: now, ToolName: "exec_cmd", Action: "block", Method: "tools/call"},
		{Timestamp: now, ToolName: "read_file", Action: "pass", Method: "tools/call"},
		{Timestamp: now, ToolName: "read_file", Action: "pass", Method: "tools/call"},
		{Timestamp: now, ToolName: "read_file", Action: "block", Method: "tools/call"},
	})

	handler := handleAnalytics(path, "tool")
	req := httptest.NewRequest(http.MethodGet, "/api/analytics/by-tool", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp analyticsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.Len(t, resp.Groups, 2)

	// read_file (3 entries) comes first due to total desc sort
	assert.Equal(t, "read_file", resp.Groups[0].Key)
	assert.Equal(t, 3, resp.Groups[0].Total)
	assert.Equal(t, 2, resp.Groups[0].Passed)
	assert.Equal(t, 1, resp.Groups[0].Blocked)

	assert.Equal(t, "exec_cmd", resp.Groups[1].Key)
	assert.Equal(t, 2, resp.Groups[1].Total)
	assert.Equal(t, 0, resp.Groups[1].Passed)
	assert.Equal(t, 2, resp.Groups[1].Blocked)
	assert.InDelta(t, 1.0, resp.Groups[1].BlockRate, 0.01)
}

func TestAnalyticsByUser(t *testing.T) {
	now := time.Now()
	path := writeTestAuditLog(t, []audit.Entry{
		{Timestamp: now, Subject: "alice", Action: "pass"},
		{Timestamp: now, Subject: "alice", Action: "block"},
		{Timestamp: now, Subject: "bob", Action: "pass"},
	})

	handler := handleAnalytics(path, "subject")
	req := httptest.NewRequest(http.MethodGet, "/api/analytics/by-user", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp analyticsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Groups, 2)
}

func TestAnalyticsEmptyFile(t *testing.T) {
	handler := handleAnalytics("/nonexistent/path.jsonl", "tool")
	req := httptest.NewRequest(http.MethodGet, "/api/analytics/by-tool", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp analyticsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp.Groups)
}

func TestAnalyticsTimeFilter(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	path := writeTestAuditLog(t, []audit.Entry{
		{Timestamp: base, ToolName: "old", Action: "pass"},
		{Timestamp: base.Add(24 * time.Hour), ToolName: "new", Action: "pass"},
	})

	handler := handleAnalytics(path, "tool")
	req := httptest.NewRequest(http.MethodGet, "/api/analytics/by-tool?from="+base.Add(12*time.Hour).Format(time.RFC3339), nil)
	w := httptest.NewRecorder()
	handler(w, req)

	var resp analyticsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Groups, 1)
	assert.Equal(t, "new", resp.Groups[0].Key)
}
