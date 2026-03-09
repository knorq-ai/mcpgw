package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/policy"
)

// --- テスト用モック ---

type mockStatusProvider struct {
	upstream    string
	ready       bool
	cbState     string
	sessions    int
}

func (m *mockStatusProvider) Upstream() string              { return m.upstream }
func (m *mockStatusProvider) UpstreamReady() bool           { return m.ready }
func (m *mockStatusProvider) CircuitBreakerState() string   { return m.cbState }
func (m *mockStatusProvider) ActiveSessionCount() int       { return m.sessions }

type mockPolicyProvider struct {
	pf *policy.PolicyFile
}

func (m *mockPolicyProvider) PolicyFile() *policy.PolicyFile { return m.pf }

type mockEngineSwapper struct {
	swapped int
	last    *policy.Engine
}

func (m *mockEngineSwapper) SwapEngine(e *policy.Engine) {
	m.swapped++
	m.last = e
}

// --- ヘルパー ---

func newTestPolicyFile() *policy.PolicyFile {
	return &policy.PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []policy.Rule{
			{
				Name:   "deny-exec",
				Match:  policy.Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}},
				Action: "deny",
			},
			{
				Name:   "allow-all",
				Match:  policy.Match{Methods: []string{"*"}},
				Action: "allow",
			},
		},
	}
}

func setupMux(cfg Config) *http.ServeMux {
	mux := http.NewServeMux()
	Register(mux, cfg)
	return mux
}

// --- GET /api/status テスト ---

func TestHandleStatusGET(t *testing.T) {
	mux := setupMux(Config{
		StatusProvider: &mockStatusProvider{
			upstream: "http://localhost:8080",
			ready:    true,
			cbState:  "closed",
			sessions: 5,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp statusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "http://localhost:8080", resp.Upstream)
	assert.True(t, resp.UpstreamReady)
	assert.Equal(t, "closed", resp.CircuitBreaker)
	assert.Equal(t, 5, resp.ActiveSessions)
}

func TestHandleStatusNilProvider(t *testing.T) {
	mux := setupMux(Config{})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp statusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "", resp.Upstream)
}

func TestHandleStatusMethodNotAllowed(t *testing.T) {
	mux := setupMux(Config{
		StatusProvider: &mockStatusProvider{},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- GET /api/policy テスト ---

func TestHandlePolicyGET(t *testing.T) {
	pf := newTestPolicyFile()
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: pf},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/policy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp policyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "v1", resp.Version)
	assert.Equal(t, "enforce", resp.Mode)
	assert.Len(t, resp.Rules, 2)
	assert.Equal(t, "deny-exec", resp.Rules[0].Name)
	assert.Equal(t, "deny", resp.Rules[0].Action)
	assert.Equal(t, "allow-all", resp.Rules[1].Name)
}

func TestHandlePolicyGETNilProvider(t *testing.T) {
	mux := setupMux(Config{})

	req := httptest.NewRequest(http.MethodGet, "/api/policy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp policyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Empty(t, resp.Rules)
}

func TestHandlePolicyMethodNotAllowed(t *testing.T) {
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/policy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- GET /api/audit テスト ---

func TestHandleAuditGET(t *testing.T) {
	// 一時ファイルに監査ログを書き込む
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	entries := []audit.Entry{
		{
			Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Direction: "c2s",
			Method:    "tools/call",
			Kind:      "request",
			Size:      100,
			Action:    "pass",
		},
		{
			Timestamp: time.Date(2025, 1, 1, 0, 1, 0, 0, time.UTC),
			Direction: "c2s",
			Method:    "tools/call",
			Kind:      "request",
			Size:      200,
			Action:    "block",
			Reason:    "denied by policy",
		},
	}

	var lines []string
	for _, e := range entries {
		b, _ := json.Marshal(e)
		lines = append(lines, string(b))
	}
	require.NoError(t, os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0644))

	mux := setupMux(Config{AuditLogPath: logPath})

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp auditResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Entries, 2)
	// 新しい順（逆順）で返される
	assert.Equal(t, "block", resp.Entries[0].Action)
	assert.Equal(t, "pass", resp.Entries[1].Action)
}

func TestHandleAuditGETWithFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	entries := []audit.Entry{
		{Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), Direction: "c2s", Method: "tools/call", Action: "pass"},
		{Timestamp: time.Date(2025, 1, 1, 0, 1, 0, 0, time.UTC), Direction: "c2s", Method: "tools/list", Action: "pass"},
		{Timestamp: time.Date(2025, 1, 1, 0, 2, 0, 0, time.UTC), Direction: "c2s", Method: "tools/call", Action: "block"},
	}
	var lines []string
	for _, e := range entries {
		b, _ := json.Marshal(e)
		lines = append(lines, string(b))
	}
	require.NoError(t, os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0644))

	mux := setupMux(Config{AuditLogPath: logPath})

	req := httptest.NewRequest(http.MethodGet, "/api/audit?action=block", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp auditResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Entries, 1)
	assert.Equal(t, "block", resp.Entries[0].Action)
}

func TestHandleAuditGETNoFile(t *testing.T) {
	mux := setupMux(Config{AuditLogPath: "/nonexistent/audit.jsonl"})

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp auditResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 0, resp.Total)
}

func TestHandleAuditEmptyPath(t *testing.T) {
	mux := setupMux(Config{AuditLogPath: ""})

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp auditResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 0, resp.Total)
}

// --- PUT /api/policy テスト ---

func TestHandlePolicyPUT(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")

	// 既存ポリシーを書き込み
	oldPolicy := `version: v1
mode: enforce
rules:
  - name: allow-all
    match:
      methods: ["*"]
    action: allow
`
	require.NoError(t, os.WriteFile(policyPath, []byte(oldPolicy), 0644))

	swapper := &mockEngineSwapper{}
	pf := newTestPolicyFile()
	mux := setupMux(Config{
		PolicyPath:     policyPath,
		PolicyProvider: &mockPolicyProvider{pf: pf},
		EngineSwappers: []EngineSwapper{swapper},
	})

	newPolicy := `version: v1
mode: enforce
rules:
  - name: deny-exec
    match:
      methods: ["tools/call"]
      tools: ["exec_*"]
    action: deny
  - name: allow-all
    match:
      methods: ["*"]
    action: allow
`
	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(newPolicy))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp policyUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.OK)
	require.NotNil(t, resp.Policy)
	assert.Equal(t, "v1", resp.Policy.Version)
	assert.Equal(t, "enforce", resp.Policy.Mode)
	assert.Len(t, resp.Policy.Rules, 2)

	// SwapEngine が呼ばれたことを確認
	assert.Equal(t, 1, swapper.swapped)
	assert.NotNil(t, swapper.last)

	// ファイルが更新されていることを確認
	written, err := os.ReadFile(policyPath)
	require.NoError(t, err)
	assert.Equal(t, newPolicy, string(written))

	// バックアップが作成されていることを確認
	bakPath := policyPath + ".bak"
	bak, err := os.ReadFile(bakPath)
	require.NoError(t, err)
	assert.Equal(t, oldPolicy, string(bak))
}

func TestHandlePolicyPUTMultipleSwappers(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(`version: v1
mode: enforce
rules:
  - name: allow-all
    match:
      methods: ["*"]
    action: allow
`), 0644))

	swapper1 := &mockEngineSwapper{}
	swapper2 := &mockEngineSwapper{}
	mux := setupMux(Config{
		PolicyPath:     policyPath,
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
		EngineSwappers: []EngineSwapper{swapper1, swapper2},
	})

	newPolicy := `version: v1
mode: enforce
rules:
  - name: allow-all
    match:
      methods: ["*"]
    action: allow
`
	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(newPolicy))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, swapper1.swapped)
	assert.Equal(t, 1, swapper2.swapped)
}

func TestHandlePolicyPUTInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(""), 0644))

	mux := setupMux(Config{
		PolicyPath:     policyPath,
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
	})

	// 不正な YAML
	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader("not: [valid: yaml:"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp policyUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.OK)
	assert.Contains(t, resp.Error, "policy validation failed")
}

func TestHandlePolicyPUTInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(""), 0644))

	mux := setupMux(Config{
		PolicyPath:     policyPath,
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
	})

	// バージョンが不正
	invalidPolicy := `version: v2
mode: enforce
rules:
  - name: allow-all
    match:
      methods: ["*"]
    action: allow
`
	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(invalidPolicy))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp policyUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.OK)
	assert.Contains(t, resp.Error, "unsupported version")
}

func TestHandlePolicyPUTEmptyBody(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")

	mux := setupMux(Config{
		PolicyPath:     policyPath,
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
	})

	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(""))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp policyUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp.Error, "empty request body")
}

func TestHandlePolicyPUTNoPath(t *testing.T) {
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
	})

	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader("version: v1"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp policyUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp.Error, "policy path is not configured")
}

func TestHandlePolicyPUTNewFile(t *testing.T) {
	// ポリシーファイルが存在しない場合（新規作成）
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "new_policy.yaml")

	swapper := &mockEngineSwapper{}
	mux := setupMux(Config{
		PolicyPath:     policyPath,
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
		EngineSwappers: []EngineSwapper{swapper},
	})

	newPolicy := `version: v1
mode: enforce
rules:
  - name: allow-all
    match:
      methods: ["*"]
    action: allow
`
	req := httptest.NewRequest(http.MethodPut, "/api/policy", strings.NewReader(newPolicy))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp policyUpdateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.OK)

	// バックアップは作成されない（元ファイルが存在しないため）
	bakPath := policyPath + ".bak"
	_, err := os.Stat(bakPath)
	assert.True(t, os.IsNotExist(err))

	// SwapEngine が呼ばれたことを確認
	assert.Equal(t, 1, swapper.swapped)
}

// --- POST /api/policy/test テスト ---

func TestHandlePolicyTestPOST(t *testing.T) {
	pf := newTestPolicyFile()
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: pf},
	})

	body := testRequest{
		Scenarios: []testScenario{
			{
				Name:   "exec is denied",
				Method: "tools/call",
				Params: `{"name":"exec_cmd"}`,
				Expect: "deny",
			},
			{
				Name:   "read is allowed",
				Method: "tools/call",
				Params: `{"name":"read_file"}`,
				Expect: "allow",
			},
			{
				Name:   "list is allowed",
				Method: "tools/list",
				Expect: "allow",
			},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/policy/test", strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp testResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 3, resp.Total)
	assert.Equal(t, 3, resp.Passed)
	assert.Equal(t, 0, resp.Failed)
	assert.Len(t, resp.Results, 3)

	// 個々の結果を確認
	assert.True(t, resp.Results[0].Pass)
	assert.Equal(t, "deny", resp.Results[0].Actual)
	assert.Equal(t, "deny-exec", resp.Results[0].RuleName)

	assert.True(t, resp.Results[1].Pass)
	assert.Equal(t, "allow", resp.Results[1].Actual)
	assert.Equal(t, "allow-all", resp.Results[1].RuleName)

	assert.True(t, resp.Results[2].Pass)
	assert.Equal(t, "allow", resp.Results[2].Actual)
}

func TestHandlePolicyTestPOSTWithFailure(t *testing.T) {
	pf := newTestPolicyFile()
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: pf},
	})

	body := testRequest{
		Scenarios: []testScenario{
			{
				Name:   "expect allow but denied",
				Method: "tools/call",
				Params: `{"name":"exec_cmd"}`,
				Expect: "allow", // 実際には deny される
			},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/policy/test", strings.NewReader(string(bodyJSON)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp testResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 0, resp.Passed)
	assert.Equal(t, 1, resp.Failed)
	assert.False(t, resp.Results[0].Pass)
	assert.Equal(t, "allow", resp.Results[0].Expect)
	assert.Equal(t, "deny", resp.Results[0].Actual)
}

func TestHandlePolicyTestPOSTWithSubjectAndRoles(t *testing.T) {
	pf := &policy.PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []policy.Rule{
			{
				Name:   "admin-exec",
				Match:  policy.Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}, Roles: []string{"admin"}},
				Action: "allow",
			},
			{
				Name:   "deny-exec",
				Match:  policy.Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}},
				Action: "deny",
			},
			{
				Name:   "allow-all",
				Match:  policy.Match{Methods: []string{"*"}},
				Action: "allow",
			},
		},
	}
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: pf},
	})

	body := testRequest{
		Scenarios: []testScenario{
			{
				Name:    "admin can exec",
				Method:  "tools/call",
				Params:  `{"name":"exec_cmd"}`,
				Subject: "admin-alice",
				Roles:   []string{"admin"},
				Expect:  "allow",
			},
			{
				Name:    "user cannot exec",
				Method:  "tools/call",
				Params:  `{"name":"exec_cmd"}`,
				Subject: "user-bob",
				Expect:  "deny",
			},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/policy/test", strings.NewReader(string(bodyJSON)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp testResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Passed)
	assert.Equal(t, 0, resp.Failed)
}

func TestHandlePolicyTestPOSTEmptyScenarios(t *testing.T) {
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
	})

	body := testRequest{Scenarios: []testScenario{}}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/policy/test", strings.NewReader(string(bodyJSON)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandlePolicyTestPOSTInvalidJSON(t *testing.T) {
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/policy/test", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandlePolicyTestPOSTValidationErrors(t *testing.T) {
	pf := newTestPolicyFile()
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: pf},
	})

	tests := []struct {
		name     string
		scenario testScenario
		errMsg   string
	}{
		{
			name:     "missing name",
			scenario: testScenario{Method: "tools/call", Expect: "allow"},
			errMsg:   "name is required",
		},
		{
			name:     "missing method",
			scenario: testScenario{Name: "test", Expect: "allow"},
			errMsg:   "method is required",
		},
		{
			name:     "invalid expect",
			scenario: testScenario{Name: "test", Method: "tools/call", Expect: "maybe"},
			errMsg:   "expect must be",
		},
		{
			name:     "invalid params json",
			scenario: testScenario{Name: "test", Method: "tools/call", Params: "not json", Expect: "allow"},
			errMsg:   "params is not valid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := testRequest{Scenarios: []testScenario{tt.scenario}}
			bodyJSON, _ := json.Marshal(body)

			req := httptest.NewRequest(http.MethodPost, "/api/policy/test", strings.NewReader(string(bodyJSON)))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)

			var errResp map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
			assert.Contains(t, errResp["error"], tt.errMsg)
		})
	}
}

func TestHandlePolicyTestPOSTNilProvider(t *testing.T) {
	mux := setupMux(Config{})

	body := testRequest{
		Scenarios: []testScenario{
			{Name: "test", Method: "tools/call", Expect: "allow"},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/policy/test", strings.NewReader(string(bodyJSON)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandlePolicyTestPOSTNilPolicyFile(t *testing.T) {
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: nil},
	})

	body := testRequest{
		Scenarios: []testScenario{
			{Name: "test", Method: "tools/call", Expect: "allow"},
		},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/policy/test", strings.NewReader(string(bodyJSON)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandlePolicyTestMethodNotAllowed(t *testing.T) {
	mux := setupMux(Config{
		PolicyProvider: &mockPolicyProvider{pf: newTestPolicyFile()},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/policy/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// --- itoa テスト ---

func TestItoa(t *testing.T) {
	assert.Equal(t, "0", itoa(0))
	assert.Equal(t, "1", itoa(1))
	assert.Equal(t, "42", itoa(42))
	assert.Equal(t, "100", itoa(100))
}
