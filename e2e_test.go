package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

// TestMain はテスト実行前にバイナリをビルドし、テスト後に削除する。
var binaryPath string

func TestMain(m *testing.M) {
	// テスト用バイナリをビルド
	dir, err := os.MkdirTemp("", "mcpgw-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: temp dir: %v\n", err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "mcpgw")

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: build failed: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	os.RemoveAll(dir)
	os.Exit(code)
}

// runMcpgw はビルド済みバイナリに stdin を渡し、stdout と stderr を返す。
func runMcpgw(t *testing.T, args []string, stdin string) (stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		// 非ゼロ終了は呼び出し側で判断する
		t.Logf("mcpgw exited with error: %v\nstderr: %s", err, errBuf.String())
	}
	return outBuf.String(), errBuf.String()
}

// parseOutputMessages は stdout を NDJSON としてパースし、ID→Message マップを返す。
func parseOutputMessages(t *testing.T, stdout string) map[string]*jsonrpc.Message {
	t.Helper()
	byID := map[string]*jsonrpc.Message{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line == "" {
			continue
		}
		var msg jsonrpc.Message
		require.NoError(t, json.Unmarshal([]byte(line), &msg))
		byID[string(msg.ID)] = &msg
	}
	return byID
}

// --- E2E Tests ---

func TestE2EWrapCatEcho(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	}, "\n") + "\n"

	stdout, stderr := runMcpgw(t, []string{"wrap", "--audit-log", logPath, "--", "cat"}, input)
	_ = stderr

	// cat がエコーするため3メッセージ返る
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.Len(t, lines, 3)

	msgs := parseOutputMessages(t, stdout)

	// initialize (request)
	require.NotNil(t, msgs["1"])
	assert.Equal(t, "initialize", msgs["1"].Method)
	assert.Nil(t, msgs["1"].Error)

	// tools/list (request)
	require.NotNil(t, msgs["2"])
	assert.Equal(t, "tools/list", msgs["2"].Method)

	// 監査ログが記録されていることを確認
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logLines := strings.Split(strings.TrimSpace(string(logData)), "\n")
	// C→S: 3メッセージ + S→C: 3メッセージ(cat エコー) = 6エントリ
	assert.Len(t, logLines, 6, "監査ログに6エントリ記録されるべき")
}

func TestE2EWrapWithPolicyBlock(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	policyPath := "testdata/policy_deny_tools.yaml"

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_cmd","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`,
	}, "\n") + "\n"

	stdout, stderr := runMcpgw(t, []string{
		"wrap", "--audit-log", logPath, "--policy", policyPath, "--", "cat",
	}, input)

	// ポリシーがロードされたことを stderr で確認
	assert.Contains(t, stderr, "policy loaded")

	msgs := parseOutputMessages(t, stdout)

	// id=1: initialize → 許可
	require.NotNil(t, msgs["1"])
	assert.Equal(t, "initialize", msgs["1"].Method)
	assert.Nil(t, msgs["1"].Error)

	// id=2: exec_cmd → ブロック（エラーレスポンス）
	require.NotNil(t, msgs["2"])
	require.NotNil(t, msgs["2"].Error, "exec_cmd はブロックされるべき")
	assert.Equal(t, -32600, msgs["2"].Error.Code)
	assert.Contains(t, msgs["2"].Error.Message, "deny-exec")

	// id=3: read_file → 許可（deny-exec のツールパターンにマッチしない）
	require.NotNil(t, msgs["3"])
	assert.Equal(t, "tools/call", msgs["3"].Method)
	assert.Nil(t, msgs["3"].Error)

	// id=4: tools/list → 許可
	require.NotNil(t, msgs["4"])
	assert.Equal(t, "tools/list", msgs["4"].Method)
	assert.Nil(t, msgs["4"].Error)

	// 監査ログにブロックエントリが含まれることを確認
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logLines := strings.Split(strings.TrimSpace(string(logData)), "\n")

	foundBlock := false
	for _, line := range logLines {
		var entry audit.Entry
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		if entry.Method == "tools/call" && entry.Action == "block" {
			assert.Contains(t, entry.Reason, "deny-exec")
			foundBlock = true
		}
	}
	assert.True(t, foundBlock, "ブロックされた tools/call の監査エントリが存在すべき")
}

func TestE2EWrapPolicyAuditMode(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// audit モードのポリシーファイルを作成
	policyContent := `version: v1
mode: audit
rules:
  - name: deny-all
    match:
      methods: ["*"]
    action: deny
`
	policyPath := filepath.Join(dir, "audit_policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(policyContent), 0o600))

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_cmd"}}` + "\n"

	stdout, _ := runMcpgw(t, []string{
		"wrap", "--audit-log", logPath, "--policy", policyPath, "--", "cat",
	}, input)

	// audit モードではブロックしない — メッセージが通過する
	msgs := parseOutputMessages(t, stdout)
	require.NotNil(t, msgs["1"])
	assert.Equal(t, "tools/call", msgs["1"].Method)
	assert.Nil(t, msgs["1"].Error, "audit モードではブロックしない")
}

func TestE2EWrapNoPolicy(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool"}}` + "\n"

	stdout, _ := runMcpgw(t, []string{
		"wrap", "--audit-log", logPath, "--", "cat",
	}, input)

	// ポリシー未指定 → 全て通過
	msgs := parseOutputMessages(t, stdout)
	require.NotNil(t, msgs["1"])
	assert.Equal(t, "tools/call", msgs["1"].Method)
	assert.Nil(t, msgs["1"].Error)
}

func TestE2EWrapInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte("not: valid: policy"), 0o600))

	cmd := exec.Command(binaryPath, "wrap", "--policy", policyPath, "--", "cat")
	cmd.Stdin = strings.NewReader("")
	err := cmd.Run()
	// 不正なポリシーではエラー終了する
	assert.Error(t, err)
}

func TestE2EPolicyValidate(t *testing.T) {
	// 有効なポリシーファイル
	cmd := exec.Command(binaryPath, "policy", "validate", "testdata/policy_deny_tools.yaml")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, "有効なポリシーの validate は成功すべき: %s", string(out))

	// 無効なポリシーファイル
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badPath, []byte("version: v99\nmode: enforce\nrules: []"), 0o600))
	cmd = exec.Command(binaryPath, "policy", "validate", badPath)
	err = cmd.Run()
	assert.Error(t, err, "無効なポリシーの validate はエラー終了すべき")
}

func TestE2EVersion(t *testing.T) {
	cmd := exec.Command(binaryPath, "version")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(out), "mcpgw")
}

func TestE2EWrapLargeMessageFlow(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// 20メッセージの大量フローをテスト
	var messages []string
	for i := 1; i <= 20; i++ {
		messages = append(messages, fmt.Sprintf(
			`{"jsonrpc":"2.0","id":%d,"method":"tools/list","params":{}}`, i))
	}
	input := strings.Join(messages, "\n") + "\n"

	stdout, _ := runMcpgw(t, []string{
		"wrap", "--audit-log", logPath, "--", "cat",
	}, input)

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	assert.Len(t, lines, 20, "20メッセージ全てが通過すべき")

	// 監査ログに 40 エントリ（20 C→S + 20 S→C）
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logLines := strings.Split(strings.TrimSpace(string(logData)), "\n")
	assert.Len(t, logLines, 40)
}

// --- HTTP Proxy E2E Tests ---

// fakeUpstreamMCP は JSON-RPC リクエストにエコーレスポンスを返すフェイク MCP upstream。
func fakeUpstreamMCP(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var msg jsonrpc.Message
			if err := json.Unmarshal(body, &msg); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			resp := jsonrpc.Message{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Result:  json.RawMessage(`{"echo":"` + msg.Method + `"}`),
			}
			if msg.Method == "initialize" {
				w.Header().Set("Mcp-Session-Id", "test-session")
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
}

// getFreePort は利用可能なポートを取得する。
func getFreePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	l.Close()
	return addr
}

// waitForTCP はアドレスが TCP 接続を受け付けるまで待つ。タイムアウトで失敗する。
func waitForTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("proxy did not start listening on %s within %s", addr, timeout)
}

// startProxy はプロキシプロセスを起動し、リッスン開始を待つ。
func startProxy(t *testing.T, args []string) (*exec.Cmd, string) {
	t.Helper()
	listenAddr := getFreePort(t)
	fullArgs := append([]string{"proxy", "--listen", listenAddr}, args...)
	cmd := exec.Command(binaryPath, fullArgs...)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
	})

	waitForTCP(t, listenAddr, 5*time.Second)

	return cmd, "http://" + listenAddr
}

// httpPost は JSON-RPC リクエストを POST で送信し、レスポンスを返す。
func httpPost(t *testing.T, url string, body string, headers map[string]string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestE2EProxyBasicFlow(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--audit-log", logPath,
	})

	// JSON-RPC リクエスト送信
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	resp := httpPost(t, proxyURL, body, nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	assert.Equal(t, json.RawMessage(`1`), msg.ID)
	assert.NotNil(t, msg.Result)

	// Mcp-Session-Id が伝播されている
	assert.Equal(t, "test-session", resp.Header.Get("Mcp-Session-Id"))

	// 監査ログが記録されている（レスポンス返却前に同期書き込みされる）
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.True(t, len(logData) > 0, "監査ログが記録されるべき")
}

func TestE2EProxyPolicyBlock(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--policy", "testdata/policy_deny_tools.yaml",
	})

	// exec_cmd → ブロック
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_cmd"}}`
	resp := httpPost(t, proxyURL, body, nil)
	defer resp.Body.Close()

	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	require.NotNil(t, msg.Error)
	assert.Equal(t, -32600, msg.Error.Code)
	assert.Contains(t, msg.Error.Message, "deny-exec")

	// read_file → 許可
	body2 := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}`
	resp2 := httpPost(t, proxyURL, body2, nil)
	defer resp2.Body.Close()

	var msg2 jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&msg2))
	assert.Nil(t, msg2.Error)
	assert.NotNil(t, msg2.Result)
}

func TestE2EProxyJWTAuth(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	secret := "e2e-jwt-secret-key-for-testing!"

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--auth-jwt-algorithm", "HS256",
		"--auth-jwt-secret", secret,
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// 認証なし → 401
	resp := httpPost(t, proxyURL, body, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// 不正トークン → 401
	resp = httpPost(t, proxyURL, body, map[string]string{
		"Authorization": "Bearer invalid-token",
	})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// 有効トークン → 200
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "e2e-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	resp = httpPost(t, proxyURL, body, map[string]string{
		"Authorization": "Bearer " + tokenStr,
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	assert.NotNil(t, msg.Result)
}

func TestE2EProxyAPIKeyAuth(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--auth-apikeys", "key-alpha,key-beta",
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// 認証なし → 401
	resp := httpPost(t, proxyURL, body, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// 不正キー → 401
	resp = httpPost(t, proxyURL, body, map[string]string{
		"X-API-Key": "wrong-key",
	})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// 有効キー (X-API-Key ヘッダ) → 200
	resp = httpPost(t, proxyURL, body, map[string]string{
		"X-API-Key": "key-alpha",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 有効キー (Authorization ヘッダ) → 200
	resp2 := httpPost(t, proxyURL, body, map[string]string{
		"Authorization": "ApiKey key-beta",
	})
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

// --- RBAC E2E Tests ---

func TestE2EProxyRBACAdminAllowed(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	secret := "rbac-e2e-secret-key-for-testing!"

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--policy", "testdata/policy_rbac.yaml",
		"--auth-jwt-algorithm", "HS256",
		"--auth-jwt-secret", secret,
	})

	// admin-alice が exec_cmd を呼ぶ → admin-exec ルールで許可
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "admin-alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_cmd"}}`
	resp := httpPost(t, proxyURL, body, map[string]string{
		"Authorization": "Bearer " + tokenStr,
	})
	defer resp.Body.Close()

	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	assert.Nil(t, msg.Error, "admin-alice は exec_cmd を許可されるべき")
	assert.NotNil(t, msg.Result)
}

func TestE2EProxyRBACUserDenied(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	secret := "rbac-e2e-secret-key-for-testing!"

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--policy", "testdata/policy_rbac.yaml",
		"--auth-jwt-algorithm", "HS256",
		"--auth-jwt-secret", secret,
	})

	// user-bob が exec_cmd を呼ぶ → deny-exec ルールで拒否
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-bob",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secret))
	require.NoError(t, err)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_cmd"}}`
	resp := httpPost(t, proxyURL, body, map[string]string{
		"Authorization": "Bearer " + tokenStr,
	})
	defer resp.Body.Close()

	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	require.NotNil(t, msg.Error, "user-bob は exec_cmd を拒否されるべき")
	assert.Contains(t, msg.Error.Message, "deny-exec")
}

func TestE2EProxyRBACNoAuthDenied(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	// 認証なし + RBAC policy → subjects ルールにマッチしない → exec は deny
	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--policy", "testdata/policy_rbac.yaml",
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_cmd"}}`
	resp := httpPost(t, proxyURL, body, nil)
	defer resp.Body.Close()

	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	require.NotNil(t, msg.Error, "未認証は exec_cmd を拒否されるべき（fail-closed）")
	assert.Contains(t, msg.Error.Message, "deny-exec")

	// ただし tools/list は default-allow で許可
	body2 := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	resp2 := httpPost(t, proxyURL, body2, nil)
	defer resp2.Body.Close()

	var msg2 jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&msg2))
	assert.Nil(t, msg2.Error, "tools/list は default-allow で許可されるべき")
}

// --- Rate Limit E2E Tests ---

func TestE2EProxyRateLimit(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: %s
rate_limit:
  requests_per_second: 100
  burst: 3
`, upstream.URL)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	_, proxyURL := startProxy(t, []string{
		"--config", cfgPath,
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

	// バースト内は通過
	for i := 0; i < 3; i++ {
		resp := httpPost(t, proxyURL, body, nil)
		var msg jsonrpc.Message
		json.NewDecoder(resp.Body).Decode(&msg)
		resp.Body.Close()
		assert.Nil(t, msg.Error, "request %d should pass within burst", i)
	}

	// バースト超過 → エラーコード -32429
	resp := httpPost(t, proxyURL, body, nil)
	defer resp.Body.Close()

	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	require.NotNil(t, msg.Error, "burst 超過でブロックされるべき")
	assert.Equal(t, -32429, msg.Error.Code)
	assert.Contains(t, msg.Error.Message, "rate limit exceeded")
}

// --- Config File E2E Tests ---

func TestE2EProxyConfigFile(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: %s
listen: ":0"
`, upstream.URL)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	// --config フラグで設定ファイルから upstream を読み込み
	listenAddr := getFreePort(t)
	fullArgs := []string{"proxy", "--config", cfgPath, "--listen", listenAddr}
	cmd := exec.Command(binaryPath, fullArgs...)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
	})

	waitForTCP(t, listenAddr, 5*time.Second)

	proxyURL := "http://" + listenAddr
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	resp := httpPost(t, proxyURL, body, nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	assert.NotNil(t, msg.Result)
}

func TestE2EProxyConfigFileWithCLIOverride(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// 設定ファイルで upstream を無効な URL に設定
	cfgContent := `
upstream: http://127.0.0.1:1
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	// CLI で upstream を上書き
	_, proxyURL := startProxy(t, []string{
		"--config", cfgPath,
		"--upstream", upstream.URL,
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	resp := httpPost(t, proxyURL, body, nil)
	defer resp.Body.Close()

	// CLI の upstream が優先されるため成功する
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	assert.NotNil(t, msg.Result, "CLI フラグが設定ファイルを上書きすべき")
}

// --- TLS E2E Tests ---

// generateSelfSignedCert はテスト用自己署名証明書を生成し、cert.pem/key.pem のパスを返す。
func generateSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	certFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPath = filepath.Join(dir, "key.pem")
	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	keyFile.Close()

	return certPath, keyPath
}

// waitForTLS はアドレスが TLS 接続を受け付けるまで待つ。タイムアウトで失敗する。
func waitForTLS(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}, "tcp", addr, tlsConf)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("TLS proxy did not start listening on %s within %s", addr, timeout)
}

// startProxyTLS は TLS 対応プロキシプロセスを起動する。
func startProxyTLS(t *testing.T, args []string) (*exec.Cmd, string) {
	t.Helper()
	listenAddr := getFreePort(t)
	fullArgs := append([]string{"proxy", "--listen", listenAddr}, args...)
	cmd := exec.Command(binaryPath, fullArgs...)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
	})

	waitForTLS(t, listenAddr, 5*time.Second)

	return cmd, "https://" + listenAddr
}

func TestE2EProxyTLS(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	certPath, keyPath := generateSelfSignedCert(t)

	_, proxyURL := startProxyTLS(t, []string{
		"--upstream", upstream.URL,
		"--tls-cert", certPath,
		"--tls-key", keyPath,
	})

	// TLS クライアント（自己署名証明書を受け入れる）
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := tlsClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	assert.NotNil(t, msg.Result)
}

// --- Policy Hot-Reload E2E Tests ---

func TestE2EProxyPolicyHotReload(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	// 初期ポリシー: tools/call を全拒否
	initialPolicy := `version: v1
mode: enforce
rules:
  - name: deny-tools
    match:
      methods: ["tools/call"]
    action: deny
  - name: allow-rest
    match:
      methods: ["*"]
    action: allow
`
	require.NoError(t, os.WriteFile(policyFile, []byte(initialPolicy), 0o600))

	cmd, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--policy", policyFile,
	})

	// tools/call → ブロックされるべき
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`
	resp := httpPost(t, proxyURL, body, nil)
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	resp.Body.Close()
	require.NotNil(t, msg.Error, "初期ポリシーで tools/call はブロックされるべき")
	assert.Contains(t, msg.Error.Message, "deny-tools")

	// ポリシーファイルを書き換え: 全許可
	updatedPolicy := `version: v1
mode: enforce
rules:
  - name: allow-all
    match:
      methods: ["*"]
    action: allow
`
	require.NoError(t, os.WriteFile(policyFile, []byte(updatedPolicy), 0o600))

	// SIGHUP 送信
	require.NoError(t, cmd.Process.Signal(syscall.SIGHUP))

	// リロード反映をリトライで確認（最大 2 秒）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp2 := httpPost(t, proxyURL, body, nil)
		var msg2 jsonrpc.Message
		require.NoError(t, json.NewDecoder(resp2.Body).Decode(&msg2))
		resp2.Body.Close()
		if msg2.Error == nil {
			// リロード成功: 通過を確認
			assert.NotNil(t, msg2.Result)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("policy hot-reload did not take effect within 2s after SIGHUP")
}

func TestE2EProxyPolicyHotReloadInvalidKeepsOld(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	// 初期ポリシー: tools/call を拒否
	initialPolicy := `version: v1
mode: enforce
rules:
  - name: deny-tools
    match:
      methods: ["tools/call"]
    action: deny
  - name: allow-rest
    match:
      methods: ["*"]
    action: allow
`
	require.NoError(t, os.WriteFile(policyFile, []byte(initialPolicy), 0o600))

	cmd, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--policy", policyFile,
	})

	// tools/call → ブロック
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`
	resp := httpPost(t, proxyURL, body, nil)
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	resp.Body.Close()
	require.NotNil(t, msg.Error)

	// 不正なポリシーに書き換え → リロード失敗 → 旧ポリシーが維持されるべき
	require.NoError(t, os.WriteFile(policyFile, []byte("invalid yaml: [[["), 0o600))

	require.NoError(t, cmd.Process.Signal(syscall.SIGHUP))
	// リロード処理の完了を待つ
	time.Sleep(200 * time.Millisecond)

	// 旧ポリシーが維持されている → まだブロックされる
	resp2 := httpPost(t, proxyURL, body, nil)
	var msg2 jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&msg2))
	resp2.Body.Close()
	require.NotNil(t, msg2.Error, "不正ポリシーでのリロード後も旧ポリシーが維持されるべき")
	assert.Contains(t, msg2.Error.Message, "deny-tools")
}

// --- Request ID E2E Tests ---

func TestE2EProxyRequestID(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// クライアントが X-Request-Id を指定しなかった場合 → 自動生成
	resp := httpPost(t, proxyURL, body, nil)
	defer resp.Body.Close()

	reqID := resp.Header.Get("X-Request-Id")
	assert.NotEmpty(t, reqID, "X-Request-Id が自動生成されるべき")
	assert.Len(t, reqID, 32, "16 bytes hex = 32 chars")

	// クライアントが X-Request-Id を指定した場合 → そのまま伝播
	resp2 := httpPost(t, proxyURL, body, map[string]string{
		"X-Request-Id": "custom-req-id",
	})
	defer resp2.Body.Close()

	assert.Equal(t, "custom-req-id", resp2.Header.Get("X-Request-Id"))
}

// --- CORS E2E Tests ---

func TestE2EProxyCORS(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: %s
cors:
  allowed_origins:
    - "http://example.com"
`, upstream.URL)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	_, proxyURL := startProxy(t, []string{
		"--config", cfgPath,
	})

	// OPTIONS プリフライト → 204
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, proxyURL, nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "http://example.com")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "http://example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Headers"), "Content-Type")

	// 許可されていないオリジン → CORS ヘッダなし
	req2, err := http.NewRequestWithContext(ctx, http.MethodOptions, proxyURL, nil)
	require.NoError(t, err)
	req2.Header.Set("Origin", "http://evil.com")
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Empty(t, resp2.Header.Get("Access-Control-Allow-Origin"))
}

// --- Batch JSON-RPC E2E Tests ---

func TestE2EProxyBatchJSONRPC(t *testing.T) {
	upstream := fakeUpstreamMCPBatch(t)
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	batchBody := `[
		{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
		{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
	]`
	resp := httpPost(t, proxyURL, batchBody, nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var responses []json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&responses))
	assert.Len(t, responses, 2)
}

func TestE2EProxyBatchWithPolicyBlock(t *testing.T) {
	upstream := fakeUpstreamMCPBatch(t)
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--policy", "testdata/policy_deny_tools.yaml",
	})

	batchBody := `[
		{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_cmd"}},
		{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}
	]`
	resp := httpPost(t, proxyURL, batchBody, nil)
	defer resp.Body.Close()

	var responses []json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&responses))
	// エラーレスポンス 1 + upstream レスポンス 2 = 3
	assert.Len(t, responses, 3)

	// ブロックされたメッセージを探す
	foundBlock := false
	for _, raw := range responses {
		var msg jsonrpc.Message
		json.Unmarshal(raw, &msg)
		if msg.Error != nil && msg.Error.Code == -32600 {
			foundBlock = true
			assert.Contains(t, msg.Error.Message, "deny-exec")
		}
	}
	assert.True(t, foundBlock, "ブロックされたメッセージのエラーレスポンスが存在すべき")
}

// --- Health & Metrics E2E Tests ---

func TestE2EProxyHealthAndMetrics(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	mgmtAddr := getFreePort(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: %s
metrics:
  addr: %s
`, upstream.URL, mgmtAddr)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	_, proxyURL := startProxy(t, []string{
		"--config", cfgPath,
	})

	// 管理サーバーの起動を待つ
	waitForTCP(t, mgmtAddr, 5*time.Second)

	mgmtURL := "http://" + mgmtAddr

	// /healthz
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mgmtURL+"/healthz", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var health map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&health))
	assert.Equal(t, "ok", health["status"])

	// プロキシにリクエストを送信してメトリクスを生成
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	proxyResp := httpPost(t, proxyURL, body, nil)
	proxyResp.Body.Close()

	// /metrics
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, mgmtURL+"/metrics", nil)
	require.NoError(t, err)
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	metricsBody, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	metricsStr := string(metricsBody)

	assert.Contains(t, metricsStr, "mcpgw_requests_total")
	assert.Contains(t, metricsStr, "mcpgw_request_duration_seconds")
}

// --- Mock MCP Server ---

// mcpToolDef はモック MCP サーバーに登録するツール定義。
type mcpToolDef struct {
	Name        string
	Description string
	Handler     func(args json.RawMessage) (json.RawMessage, error)
}

// mcpRecordedRequest はモック MCP サーバーが受信したリクエストの記録。
type mcpRecordedRequest struct {
	Method    string
	Params    json.RawMessage
	RequestID string // X-Request-Id ヘッダ値
	SessionID string // Mcp-Session-Id ヘッダ値
}

// mcpRequestRecorder はリクエスト記録をスレッドセーフに管理する。
type mcpRequestRecorder struct {
	mu       sync.Mutex
	requests []mcpRecordedRequest
}

func (r *mcpRequestRecorder) record(req mcpRecordedRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
}

func (r *mcpRequestRecorder) snapshot() []mcpRecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]mcpRecordedRequest, len(r.requests))
	copy(cp, r.requests)
	return cp
}

// mcpMockOpts はモック MCP サーバーの設定。
type mcpMockOpts struct {
	useSSE      bool                 // GET → SSE ストリーム対応
	tools       []mcpToolDef         // 登録ツール定義
	recorder    *mcpRequestRecorder  // リクエスト記録（nil なら記録しない）
	sseNotifyCh chan string           // SSE イベント送信チャネル（useSSE=true 時に使用）
}

// mcpToolSchema はモック MCP ツールのスキーマ定義（tools/list レスポンス用）。
type mcpToolSchema struct {
	Type string `json:"type"`
}

// mcpToolEntry はモック MCP ツールのエントリ（tools/list レスポンス用）。
type mcpToolEntry struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	InputSchema mcpToolSchema `json:"inputSchema"`
}

// mcpMockResponse はモック MCP サーバーの1メッセージに対する処理結果。
type mcpMockResponse struct {
	msg     *jsonrpc.Message  // レスポンスメッセージ（nil なら応答なし = notification）
	headers map[string]string // 追加レスポンスヘッダ
	status  int               // HTTP ステータス（0 → 200）
}

// defaultMCPTools はデフォルトのモックツール定義を返す。
func defaultMCPTools() []mcpToolDef {
	return []mcpToolDef{
		{Name: "echo", Description: "Echo input", Handler: func(args json.RawMessage) (json.RawMessage, error) {
			return json.Marshal(map[string]json.RawMessage{"echoed": args})
		}},
		{Name: "read_file", Description: "Read a file", Handler: func(args json.RawMessage) (json.RawMessage, error) {
			return json.Marshal(map[string]string{"content": "file-content-here"})
		}},
		{Name: "exec_command", Description: "Execute a command", Handler: func(args json.RawMessage) (json.RawMessage, error) {
			return json.Marshal(map[string]string{"output": "command-output"})
		}},
	}
}

// generateUUID4 は crypto/rand を使って UUID v4 を生成する。
func generateUUID4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// newMCPMockServer は MCP プロトコルに準拠したモック upstream サーバーを生成する。
func newMCPMockServer(t *testing.T, opts mcpMockOpts) *httptest.Server {
	t.Helper()

	tools := opts.tools
	if tools == nil {
		tools = defaultMCPTools()
	}

	var mu sync.Mutex
	sessions := make(map[string]bool)

	recordRequest := func(r *http.Request, method string, params json.RawMessage) {
		if opts.recorder == nil {
			return
		}
		opts.recorder.record(mcpRecordedRequest{
			Method:    method,
			Params:    params,
			RequestID: r.Header.Get("X-Request-Id"),
			SessionID: r.Header.Get("Mcp-Session-Id"),
		})
	}

	validateSession := func(r *http.Request) bool {
		sid := r.Header.Get("Mcp-Session-Id")
		if sid == "" {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		return sessions[sid]
	}

	// handleMessage は単一の JSON-RPC メッセージを処理し、レスポンスを返す。
	// 単一リクエスト・バッチリクエストの両方から呼ばれる共通ロジック。
	handleMessage := func(r *http.Request, msg jsonrpc.Message) *mcpMockResponse {
		recordRequest(r, msg.Method, msg.Params)

		switch msg.Method {
		case "initialize":
			sid := generateUUID4()
			mu.Lock()
			sessions[sid] = true
			mu.Unlock()
			return &mcpMockResponse{
				msg: &jsonrpc.Message{
					JSONRPC: "2.0",
					ID:      msg.ID,
					Result:  json.RawMessage(`{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"1.0"}}`),
				},
				headers: map[string]string{"Mcp-Session-Id": sid},
			}

		case "notifications/initialized":
			return &mcpMockResponse{status: http.StatusNoContent}

		case "tools/list":
			if !validateSession(r) {
				return &mcpMockResponse{msg: &jsonrpc.Message{
					JSONRPC: "2.0", ID: msg.ID,
					Error: &jsonrpc.ErrorObject{Code: -32001, Message: "invalid session"},
				}}
			}
			var entries []mcpToolEntry
			for _, t := range tools {
				entries = append(entries, mcpToolEntry{
					Name: t.Name, Description: t.Description,
					InputSchema: mcpToolSchema{Type: "object"},
				})
			}
			result, _ := json.Marshal(map[string]any{"tools": entries})
			return &mcpMockResponse{msg: &jsonrpc.Message{
				JSONRPC: "2.0", ID: msg.ID, Result: result,
			}}

		case "tools/call":
			if !validateSession(r) {
				return &mcpMockResponse{msg: &jsonrpc.Message{
					JSONRPC: "2.0", ID: msg.ID,
					Error: &jsonrpc.ErrorObject{Code: -32001, Message: "invalid session"},
				}}
			}
			var params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			json.Unmarshal(msg.Params, &params)

			var handler func(json.RawMessage) (json.RawMessage, error)
			for _, t := range tools {
				if t.Name == params.Name {
					handler = t.Handler
					break
				}
			}
			if handler == nil {
				return &mcpMockResponse{msg: &jsonrpc.Message{
					JSONRPC: "2.0", ID: msg.ID,
					Error: &jsonrpc.ErrorObject{Code: -32602, Message: "unknown tool: " + params.Name},
				}}
			}

			handlerResult, err := handler(params.Arguments)
			if err != nil {
				return &mcpMockResponse{msg: &jsonrpc.Message{
					JSONRPC: "2.0", ID: msg.ID,
					Error: &jsonrpc.ErrorObject{Code: -32603, Message: err.Error()},
				}}
			}

			textContent, _ := json.Marshal([]map[string]string{
				{"type": "text", "text": string(handlerResult)},
			})
			result, _ := json.Marshal(map[string]json.RawMessage{"content": textContent})
			return &mcpMockResponse{msg: &jsonrpc.Message{
				JSONRPC: "2.0", ID: msg.ID, Result: result,
			}}

		default:
			return &mcpMockResponse{msg: &jsonrpc.Message{
				JSONRPC: "2.0", ID: msg.ID,
				Error: &jsonrpc.ErrorObject{Code: -32601, Message: "Method not found"},
			}}
		}
	}

	// writeMockResponse は mcpMockResponse を HTTP レスポンスとして書き込む。
	writeMockResponse := func(w http.ResponseWriter, resp *mcpMockResponse) {
		for k, v := range resp.headers {
			w.Header().Set(k, v)
		}
		if resp.msg == nil {
			status := resp.status
			if status == 0 {
				status = http.StatusNoContent
			}
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp.msg)
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			trimmed := strings.TrimSpace(string(body))

			// バッチリクエスト検出
			if len(trimmed) > 0 && trimmed[0] == '[' {
				var rawMsgs []json.RawMessage
				if err := json.Unmarshal([]byte(trimmed), &rawMsgs); err != nil {
					http.Error(w, "Bad Request", http.StatusBadRequest)
					return
				}
				var responses []json.RawMessage
				for _, raw := range rawMsgs {
					var msg jsonrpc.Message
					if err := json.Unmarshal(raw, &msg); err != nil {
						continue
					}
					resp := handleMessage(r, msg)
					// ヘッダ（Mcp-Session-Id 等）を HTTP レスポンスに反映
					for k, v := range resp.headers {
						w.Header().Set(k, v)
					}
					// レスポンスメッセージがある場合のみ配列に追加（notification は除外）
					if resp.msg != nil {
						data, _ := json.Marshal(resp.msg)
						responses = append(responses, data)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(responses)
				return
			}

			// 単一リクエスト
			var msg jsonrpc.Message
			if err := json.Unmarshal([]byte(trimmed), &msg); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			resp := handleMessage(r, msg)
			writeMockResponse(w, resp)

		case http.MethodGet:
			if !opts.useSSE {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			if !validateSession(r) {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming not supported", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			flusher.Flush()

			if opts.sseNotifyCh != nil {
				for data := range opts.sseNotifyCh {
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
					flusher.Flush()
				}
			}

		case http.MethodDelete:
			sid := r.Header.Get("Mcp-Session-Id")
			if sid == "" {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			mu.Lock()
			existed := sessions[sid]
			delete(sessions, sid)
			mu.Unlock()
			if !existed {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
}

// httpDelete は DELETE リクエストを送信し、レスポンスを返す。
func httpDelete(t *testing.T, url string, headers map[string]string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// mcpInitialize はモック MCP サーバーに initialize リクエストを送信し、セッション ID を返す。
func mcpInitialize(t *testing.T, proxyURL string, headers map[string]string) (sessionID string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	resp := httpPost(t, proxyURL, body, headers)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	sessionID = resp.Header.Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID, "initialize は Mcp-Session-Id を返すべき")
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	require.Nil(t, msg.Error, "initialize はエラーを返さないべき")
	return sessionID
}

// --- MCP Protocol E2E Tests ---

func TestE2EMCPFullLifecycle(t *testing.T) {
	upstream := newMCPMockServer(t, mcpMockOpts{})
	defer upstream.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--audit-log", logPath,
	})

	// 1. initialize → 200、Mcp-Session-Id 取得
	sessionID := mcpInitialize(t, proxyURL, nil)

	hdrs := map[string]string{"Mcp-Session-Id": sessionID}

	// 2. notifications/initialized → 204（notification なので ID なし）
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	notifResp := httpPost(t, proxyURL, notifBody, hdrs)
	// notification はレスポンスボディが空かもしれないが、エラーでないことを確認
	notifRespBody, _ := io.ReadAll(notifResp.Body)
	notifResp.Body.Close()
	// プロキシが upstream の 204 を返すか、空ボディの 200 を返す
	assert.True(t, notifResp.StatusCode == http.StatusNoContent || notifResp.StatusCode == http.StatusOK,
		"notifications/initialized のステータスコード: %d, body: %s", notifResp.StatusCode, string(notifRespBody))

	// 3. tools/list → ツール一覧取得、3 ツール確認
	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	listResp := httpPost(t, proxyURL, listBody, hdrs)
	defer listResp.Body.Close()
	assert.Equal(t, http.StatusOK, listResp.StatusCode)
	var listMsg jsonrpc.Message
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&listMsg))
	require.Nil(t, listMsg.Error)
	var listResult struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(listMsg.Result, &listResult))
	assert.Len(t, listResult.Tools, 3, "デフォルト 3 ツールが返るべき")

	// 4. tools/call (echo) → 正常結果
	callBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hello"}}}`
	callResp := httpPost(t, proxyURL, callBody, hdrs)
	defer callResp.Body.Close()
	var callMsg jsonrpc.Message
	require.NoError(t, json.NewDecoder(callResp.Body).Decode(&callMsg))
	require.Nil(t, callMsg.Error, "echo ツール呼び出しはエラーを返さないべき")
	assert.NotNil(t, callMsg.Result)

	// 5. DELETE → 204、セッション終了
	delResp := httpDelete(t, proxyURL, hdrs)
	delResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, delResp.StatusCode)

	// 6. 終了後の POST → 404（セッション消滅）
	postAfterBody := `{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`
	postAfterResp := httpPost(t, proxyURL, postAfterBody, hdrs)
	defer postAfterResp.Body.Close()
	var postAfterMsg jsonrpc.Message
	json.NewDecoder(postAfterResp.Body).Decode(&postAfterMsg)
	// upstream がセッション無効を返す（-32001 invalid session）
	require.NotNil(t, postAfterMsg.Error, "セッション終了後のリクエストはエラーを返すべき")
}

func TestE2EMCPPolicyBlocksExecCommand(t *testing.T) {
	upstream := newMCPMockServer(t, mcpMockOpts{})
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--policy", "testdata/policy_deny_tools.yaml",
	})

	// 1. initialize → 成功
	sessionID := mcpInitialize(t, proxyURL, nil)
	hdrs := map[string]string{"Mcp-Session-Id": sessionID}

	// 2. tools/call (exec_command) → ブロック（-32600 + deny-exec）
	execBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_command","arguments":{}}}`
	execResp := httpPost(t, proxyURL, execBody, hdrs)
	defer execResp.Body.Close()
	var execMsg jsonrpc.Message
	require.NoError(t, json.NewDecoder(execResp.Body).Decode(&execMsg))
	require.NotNil(t, execMsg.Error, "exec_command はブロックされるべき")
	assert.Equal(t, -32600, execMsg.Error.Code)
	assert.Contains(t, execMsg.Error.Message, "deny-exec")

	// 3. tools/call (echo) → 成功
	echoBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"test"}}}`
	echoResp := httpPost(t, proxyURL, echoBody, hdrs)
	defer echoResp.Body.Close()
	var echoMsg jsonrpc.Message
	require.NoError(t, json.NewDecoder(echoResp.Body).Decode(&echoMsg))
	assert.Nil(t, echoMsg.Error, "echo は許可されるべき")

	// 4. tools/call (read_file) → 成功
	readBody := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	readResp := httpPost(t, proxyURL, readBody, hdrs)
	defer readResp.Body.Close()
	var readMsg jsonrpc.Message
	require.NoError(t, json.NewDecoder(readResp.Body).Decode(&readMsg))
	assert.Nil(t, readMsg.Error, "read_file は許可されるべき")
}

func TestE2EMCPSessionPersistence(t *testing.T) {
	upstream := newMCPMockServer(t, mcpMockOpts{})
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	// 1. initialize → Mcp-Session-Id 取得
	sessionID := mcpInitialize(t, proxyURL, nil)
	hdrs := map[string]string{"Mcp-Session-Id": sessionID}

	// 2. 複数の tools/call で同じセッション ID を送信 → 成功
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{"i":%d}}}`, i+10, i)
		resp := httpPost(t, proxyURL, body, hdrs)
		var msg jsonrpc.Message
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
		resp.Body.Close()
		assert.Nil(t, msg.Error, "同一セッション ID でのリクエスト %d は成功すべき", i)
	}

	// 3. 異なるセッション ID を送信 → upstream で拒否
	badHdrs := map[string]string{"Mcp-Session-Id": "non-existent-session-id"}
	body := `{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	resp := httpPost(t, proxyURL, body, badHdrs)
	defer resp.Body.Close()
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	require.NotNil(t, msg.Error, "無効なセッション ID はエラーを返すべき")
}

func TestE2EMCPSSEStreaming(t *testing.T) {
	sseNotifyCh := make(chan string, 10)
	upstream := newMCPMockServer(t, mcpMockOpts{
		useSSE:      true,
		sseNotifyCh: sseNotifyCh,
	})
	defer upstream.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--audit-log", logPath,
	})

	// 1. initialize → セッション ID 取得
	sessionID := mcpInitialize(t, proxyURL, nil)

	// 2. GET + Accept: text/event-stream + Mcp-Session-Id → SSE ストリーム開始
	getHdrs := map[string]string{
		"Accept":         "text/event-stream",
		"Mcp-Session-Id": sessionID,
	}

	// SSE イベントを送信（3 つ）
	notification1 := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"abc","progress":50}}`
	notification2 := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"abc","progress":100}}`
	notification3 := `{"jsonrpc":"2.0","method":"notifications/message","params":{"message":"done"}}`

	// SSE 受信を goroutine で開始（httpGet は context を即キャンセルするため直接リクエストを作成）
	type sseResult struct {
		events []string
		err    error
	}
	resultCh := make(chan sseResult, 1)

	sseCtx, sseCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer sseCancel()

	go func() {
		req, err := http.NewRequestWithContext(sseCtx, http.MethodGet, proxyURL, nil)
		if err != nil {
			resultCh <- sseResult{err: err}
			return
		}
		for k, v := range getHdrs {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			resultCh <- sseResult{err: err}
			return
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		var events []string
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				events = append(events, strings.TrimPrefix(line, "data: "))
			}
			if len(events) >= 3 {
				break
			}
		}
		resultCh <- sseResult{events: events, err: scanner.Err()}
	}()

	// サーバーからイベントを送信
	time.Sleep(200 * time.Millisecond) // GET 接続の確立を待つ
	sseNotifyCh <- notification1
	sseNotifyCh <- notification2
	sseNotifyCh <- notification3
	close(sseNotifyCh)

	// 結果を検証
	select {
	case result := <-resultCh:
		require.NoError(t, result.err)
		require.Len(t, result.events, 3, "3 つの SSE イベントを受信すべき")
		// 各イベントが JSON-RPC notification であることを確認
		for _, ev := range result.events {
			var msg jsonrpc.Message
			require.NoError(t, json.Unmarshal([]byte(ev), &msg), "SSE イベントは有効な JSON-RPC メッセージであるべき")
			assert.Equal(t, "2.0", msg.JSONRPC)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SSE イベント受信がタイムアウト")
	}

	// 5. 監査ログに S→C 方向のエントリが記録されていることを確認
	// ログの書き込み完了を待つ
	time.Sleep(200 * time.Millisecond)
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logLines := strings.Split(strings.TrimSpace(string(logData)), "\n")

	foundS2C := false
	for _, line := range logLines {
		var entry audit.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Direction == "s2c" {
			foundS2C = true
			break
		}
	}
	assert.True(t, foundS2C, "監査ログに s2c エントリが存在すべき")
}

func TestE2EMCPBatchLifecycle(t *testing.T) {
	upstream := newMCPMockServer(t, mcpMockOpts{})
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	// バッチで [initialize, tools/list, tools/call(echo)] を送信
	batchBody := `[
		{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
		{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},
		{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"batch"}}}
	]`
	resp := httpPost(t, proxyURL, batchBody, nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var responses []json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&responses))
	assert.Len(t, responses, 3, "3 レスポンスが返るべき")

	// 各レスポンスの id が正しく対応することを確認
	idMap := make(map[string]bool)
	for _, raw := range responses {
		var msg jsonrpc.Message
		require.NoError(t, json.Unmarshal(raw, &msg))
		assert.NotNil(t, msg.ID, "レスポンスに ID が含まれるべき")
		idStr := strings.Trim(string(msg.ID), `"`)
		idMap[idStr] = true
	}
	assert.True(t, idMap["1"], "ID=1 のレスポンスが存在すべき")
	assert.True(t, idMap["2"], "ID=2 のレスポンスが存在すべき")
	assert.True(t, idMap["3"], "ID=3 のレスポンスが存在すべき")
}

func TestE2EMCPRequestIDPropagation(t *testing.T) {
	recorder := &mcpRequestRecorder{}
	upstream := newMCPMockServer(t, mcpMockOpts{
		recorder: recorder,
	})
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	// 1. X-Request-Id: test-trace-id-123 でリクエスト送信
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	resp := httpPost(t, proxyURL, body, map[string]string{
		"X-Request-Id": "test-trace-id-123",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 2. モックサーバーの requests 記録から RequestID を取得
	requests := recorder.snapshot()
	require.NotEmpty(t, requests, "モックサーバーにリクエストが記録されるべき")

	// 3. test-trace-id-123 と一致することを確認
	found := false
	for _, req := range requests {
		if req.RequestID == "test-trace-id-123" {
			found = true
			break
		}
	}
	assert.True(t, found, "モックサーバーに到達した X-Request-Id が test-trace-id-123 であるべき")

	// 4. レスポンスヘッダにも X-Request-Id: test-trace-id-123 が含まれること
	assert.Equal(t, "test-trace-id-123", resp.Header.Get("X-Request-Id"))
}

func TestE2EMCPAuditLogCompleteness(t *testing.T) {
	upstream := newMCPMockServer(t, mcpMockOpts{})
	defer upstream.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
		"--audit-log", logPath,
		"--policy", "testdata/policy_deny_tools.yaml",
	})

	// 完全なライフサイクル: initialize → tools/list → tools/call(echo) → tools/call(exec_command) → DELETE
	// 全リクエストに X-Request-Id を付与
	reqID := "audit-test-req-001"
	hdrs := map[string]string{"X-Request-Id": reqID}

	// 1. initialize
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	initResp := httpPost(t, proxyURL, initBody, hdrs)
	sessionID := initResp.Header.Get("Mcp-Session-Id")
	initResp.Body.Close()
	require.NotEmpty(t, sessionID)

	hdrs["Mcp-Session-Id"] = sessionID

	// 2. tools/list
	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	listResp := httpPost(t, proxyURL, listBody, hdrs)
	listResp.Body.Close()

	// 3. tools/call (echo) → pass
	echoBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
	echoResp := httpPost(t, proxyURL, echoBody, hdrs)
	echoResp.Body.Close()

	// 4. tools/call (exec_command) → block
	execBody := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec_command","arguments":{}}}`
	execResp := httpPost(t, proxyURL, execBody, hdrs)
	execResp.Body.Close()

	// 5. DELETE
	delResp := httpDelete(t, proxyURL, hdrs)
	delResp.Body.Close()

	// 監査ログファイルを読み込み
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logLines := strings.Split(strings.TrimSpace(string(logData)), "\n")

	var entries []audit.Entry
	for _, line := range logLines {
		var entry audit.Entry
		require.NoError(t, json.Unmarshal([]byte(line), &entry), "監査ログ行のパースに失敗: %s", line)
		entries = append(entries, entry)
	}

	// 6. 各リクエスト/レスポンスに対応するエントリの存在を確認
	// C→S: initialize, tools/list, echo(tools/call), exec_command(tools/call) = 4
	// S→C: initialize resp, tools/list resp, echo resp = 3（exec_command はブロックされるので upstream に行かない）
	// exec_command block: c2s block = 含む
	c2sCount := 0
	s2cCount := 0
	for _, e := range entries {
		if e.Direction == "c2s" {
			c2sCount++
		} else if e.Direction == "s2c" {
			s2cCount++
		}
	}
	assert.True(t, c2sCount >= 4, "C→S エントリが 4 以上あるべき（実際: %d）", c2sCount)
	assert.True(t, s2cCount >= 3, "S→C エントリが 3 以上あるべき（実際: %d）", s2cCount)

	// 7. 全エントリに request_id が含まれることを確認
	for _, e := range entries {
		assert.NotEmpty(t, e.RequestID, "全エントリに request_id が含まれるべき（method=%s, direction=%s）", e.Method, e.Direction)
	}

	// 8. direction が c2s / s2c で正しく記録されていること
	for _, e := range entries {
		assert.True(t, e.Direction == "c2s" || e.Direction == "s2c",
			"direction は c2s または s2c であるべき（実際: %s）", e.Direction)
	}

	// 9. ブロックされたリクエストの action が block であること
	foundBlock := false
	for _, e := range entries {
		if e.Action == "block" {
			foundBlock = true
			assert.Contains(t, e.Reason, "deny-exec", "ブロック理由に deny-exec が含まれるべき")
			assert.Equal(t, "tools/call", e.Method)
			break
		}
	}
	assert.True(t, foundBlock, "ブロックされた tools/call の監査エントリが存在すべき")
}

// --- Real MCP Server (server-everything) E2E Tests ---

// findNPX は npx コマンドのパスを返す。見つからなければ空文字。
func findNPX() string {
	path, err := exec.LookPath("npx")
	if err != nil {
		return ""
	}
	return path
}

// startRealMCPServer は @modelcontextprotocol/server-everything を streamableHttp モードで起動し、
// MCP エンドポイント URL を返す。npx が見つからなければ t.Skip する。
func startRealMCPServer(t *testing.T) string {
	t.Helper()

	npx := findNPX()
	if npx == "" {
		t.Skip("npx not found; skipping real MCP server test")
	}

	addr := getFreePort(t)
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	cmd := exec.Command(npx, "-y", "@modelcontextprotocol/server-everything", "streamableHttp")
	cmd.Env = append(os.Environ(), "PORT="+port)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
		}
	})

	waitForTCP(t, addr, 30*time.Second)
	return "http://" + addr + "/mcp"
}

// realServerClient は実サーバー向けのタイムアウト長めの HTTP クライアント。
var realServerClient = &http.Client{Timeout: 30 * time.Second}

// realMCPResponse は実サーバーの MCP レスポンスを保持する。
// プロキシは upstream の SSE を SSE として中継するため、テスト側で SSE パースが必要。
type realMCPResponse struct {
	StatusCode int
	SessionID  string // Mcp-Session-Id ヘッダ
	Message    *jsonrpc.Message
}

// realServerPost は実サーバー向けに HTTP POST を送信し、SSE/JSON 両形式を透過的にパースする。
func realServerPost(t *testing.T, url string, body string, headers map[string]string) *realMCPResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := realServerClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	result := &realMCPResponse{
		StatusCode: resp.StatusCode,
		SessionID:  resp.Header.Get("Mcp-Session-Id"),
	}

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode == http.StatusNoContent || len(respBody) == 0 {
		return result
	}

	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		// SSE 形式: "data: {...}\n\n" の行から JSON を抽出
		scanner := bufio.NewScanner(strings.NewReader(string(respBody)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")
				var msg jsonrpc.Message
				if err := json.Unmarshal([]byte(data), &msg); err == nil {
					result.Message = &msg
					break
				}
			}
		}
	} else {
		// JSON 形式
		var msg jsonrpc.Message
		if err := json.Unmarshal(respBody, &msg); err == nil {
			result.Message = &msg
		}
	}

	return result
}

// realServerDelete は実サーバー向けに HTTP DELETE を送信する。
func realServerDelete(t *testing.T, url string, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := realServerClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func TestE2ERealServerFullLifecycle(t *testing.T) {
	upstreamURL := startRealMCPServer(t)

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstreamURL,
		"--policy", "testdata/policy_allow_all.yaml",
	})

	// 1. initialize → Mcp-Session-Id 取得、serverInfo.name に "everything" が含まれること
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}`
	initResp := realServerPost(t, proxyURL, initBody, nil)
	require.Equal(t, http.StatusOK, initResp.StatusCode)
	require.NotEmpty(t, initResp.SessionID, "initialize は Mcp-Session-Id を返すべき")
	require.NotNil(t, initResp.Message, "initialize はメッセージを返すべき")
	require.Nil(t, initResp.Message.Error, "initialize はエラーを返さないべき")

	// serverInfo.name の検証
	var initResult struct {
		ServerInfo struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	require.NoError(t, json.Unmarshal(initResp.Message.Result, &initResult))
	assert.Contains(t, initResult.ServerInfo.Name, "everything")

	hdrs := map[string]string{"Mcp-Session-Id": initResp.SessionID}

	// 2. notifications/initialized → 成功（202 Accepted も許容）
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	notifResp := realServerPost(t, proxyURL, notifBody, hdrs)
	assert.True(t, notifResp.StatusCode >= 200 && notifResp.StatusCode < 300,
		"notifications/initialized ステータス: %d", notifResp.StatusCode)

	// 3. tools/list → ツール一覧に echo, get-sum, get-env が含まれること
	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	listResp := realServerPost(t, proxyURL, listBody, hdrs)
	require.NotNil(t, listResp.Message)
	require.Nil(t, listResp.Message.Error)

	var listResult struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(listResp.Message.Result, &listResult))

	toolNames := make(map[string]bool)
	for _, tool := range listResult.Tools {
		toolNames[tool.Name] = true
	}
	assert.True(t, toolNames["echo"], "ツール一覧に echo が含まれるべき")
	assert.True(t, toolNames["get-sum"], "ツール一覧に get-sum が含まれるべき")
	assert.True(t, toolNames["get-env"], "ツール一覧に get-env が含まれるべき")

	// 4. tools/call (echo) → 正常結果、"hello" が含まれること
	echoBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`
	echoResp := realServerPost(t, proxyURL, echoBody, hdrs)
	require.NotNil(t, echoResp.Message)
	require.Nil(t, echoResp.Message.Error, "echo ツール呼び出しはエラーを返さないべき")
	assert.Contains(t, string(echoResp.Message.Result), "hello")

	// 5. tools/call (get-sum) → 結果に "5" が含まれること
	sumBody := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get-sum","arguments":{"a":2,"b":3}}}`
	sumResp := realServerPost(t, proxyURL, sumBody, hdrs)
	require.NotNil(t, sumResp.Message)
	require.Nil(t, sumResp.Message.Error, "get-sum ツール呼び出しはエラーを返さないべき")
	assert.Contains(t, string(sumResp.Message.Result), "5")

	// 6. DELETE → セッション終了
	delStatus := realServerDelete(t, proxyURL, hdrs)
	assert.True(t, delStatus >= 200 && delStatus < 300,
		"DELETE ステータス: %d", delStatus)
}

func TestE2ERealServerPolicyEnforcement(t *testing.T) {
	upstreamURL := startRealMCPServer(t)

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstreamURL,
		"--policy", "testdata/policy_real_server.yaml",
	})

	// 1. initialize → 成功
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}`
	initResp := realServerPost(t, proxyURL, initBody, nil)
	require.Equal(t, http.StatusOK, initResp.StatusCode)
	require.NotEmpty(t, initResp.SessionID)
	require.NotNil(t, initResp.Message)
	require.Nil(t, initResp.Message.Error)

	hdrs := map[string]string{"Mcp-Session-Id": initResp.SessionID}

	// notifications/initialized
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	realServerPost(t, proxyURL, notifBody, hdrs)

	// 2. tools/call (get-env) → ブロック（-32600 + block-env-leak）
	getEnvBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get-env","arguments":{}}}`
	getEnvResp := realServerPost(t, proxyURL, getEnvBody, hdrs)
	require.NotNil(t, getEnvResp.Message)
	require.NotNil(t, getEnvResp.Message.Error, "get-env はブロックされるべき")
	assert.Equal(t, -32600, getEnvResp.Message.Error.Code)
	assert.Contains(t, getEnvResp.Message.Error.Message, "block-env-leak")

	// 3. tools/call (trigger-long-running-operation) → ブロック（-32600 + block-long-running）
	longRunBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"trigger-long-running-operation","arguments":{}}}`
	longRunResp := realServerPost(t, proxyURL, longRunBody, hdrs)
	require.NotNil(t, longRunResp.Message)
	require.NotNil(t, longRunResp.Message.Error, "trigger-long-running-operation はブロックされるべき")
	assert.Equal(t, -32600, longRunResp.Message.Error.Code)
	assert.Contains(t, longRunResp.Message.Error.Message, "block-long-running")

	// 4. tools/call (echo) → 許可、正常結果
	echoBody := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"message":"allowed"}}}`
	echoResp := realServerPost(t, proxyURL, echoBody, hdrs)
	require.NotNil(t, echoResp.Message)
	assert.Nil(t, echoResp.Message.Error, "echo は許可されるべき")
	assert.Contains(t, string(echoResp.Message.Result), "allowed")

	// 5. tools/call (get-sum) → 許可、正常結果
	sumBody := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get-sum","arguments":{"a":10,"b":20}}}`
	sumResp := realServerPost(t, proxyURL, sumBody, hdrs)
	require.NotNil(t, sumResp.Message)
	assert.Nil(t, sumResp.Message.Error, "get-sum は許可されるべき")
	assert.Contains(t, string(sumResp.Message.Result), "30")
}

func TestE2ERealServerAuditTrail(t *testing.T) {
	upstreamURL := startRealMCPServer(t)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstreamURL,
		"--policy", "testdata/policy_real_server.yaml",
		"--audit-log", logPath,
	})

	// 1. initialize
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}`
	initResp := realServerPost(t, proxyURL, initBody, nil)
	require.NotEmpty(t, initResp.SessionID)

	hdrs := map[string]string{"Mcp-Session-Id": initResp.SessionID}

	// notifications/initialized
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	realServerPost(t, proxyURL, notifBody, hdrs)

	// 2. tools/list
	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	realServerPost(t, proxyURL, listBody, hdrs)

	// 3. tools/call (echo) → pass
	echoBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"audit-test"}}}`
	realServerPost(t, proxyURL, echoBody, hdrs)

	// 4. tools/call (get-env) → blocked
	getEnvBody := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get-env","arguments":{}}}`
	realServerPost(t, proxyURL, getEnvBody, hdrs)

	// 監査ログを検証
	logData, err := os.ReadFile(logPath)
	require.NoError(t, err)
	logLines := strings.Split(strings.TrimSpace(string(logData)), "\n")

	var entries []audit.Entry
	for _, line := range logLines {
		var entry audit.Entry
		require.NoError(t, json.Unmarshal([]byte(line), &entry), "監査ログ行のパースに失敗: %s", line)
		entries = append(entries, entry)
	}

	// 全エントリに request_id が存在すること
	for _, e := range entries {
		assert.NotEmpty(t, e.RequestID, "全エントリに request_id が含まれるべき（method=%s, direction=%s）", e.Method, e.Direction)
	}

	// direction が c2s / s2c で正しく記録されていること
	c2sCount := 0
	s2cCount := 0
	for _, e := range entries {
		assert.True(t, e.Direction == "c2s" || e.Direction == "s2c",
			"direction は c2s または s2c であるべき（実際: %s）", e.Direction)
		if e.Direction == "c2s" {
			c2sCount++
		} else {
			s2cCount++
		}
	}
	assert.True(t, c2sCount >= 4, "C→S エントリが 4 以上あるべき（実際: %d）", c2sCount)
	assert.True(t, s2cCount >= 3, "S→C エントリが 3 以上あるべき（実際: %d）", s2cCount)

	// get-env の action が block であること
	foundBlock := false
	for _, e := range entries {
		if e.Action == "block" && strings.Contains(e.Reason, "block-env-leak") {
			foundBlock = true
			assert.Equal(t, "tools/call", e.Method)
			break
		}
	}
	assert.True(t, foundBlock, "get-env の block エントリが存在すべき")

	// echo の action が pass であること（c2s で tools/call + pass）
	foundPass := false
	for _, e := range entries {
		if e.Direction == "c2s" && e.Method == "tools/call" && e.Action == "pass" {
			foundPass = true
			break
		}
	}
	assert.True(t, foundPass, "echo の pass エントリが存在すべき")
}

// --- Resilience & Performance Helper Functions ---

// mcpInitializeE は goroutine 安全な initialize（t.Fatal を呼ばない）。
func mcpInitializeE(proxyURL string) (sessionID string, err error) {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	resp, err := httpPostE(proxyURL, body, nil)
	if err != nil {
		return "", fmt.Errorf("initialize POST failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("initialize returned status %d", resp.StatusCode)
	}
	sessionID = resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		return "", fmt.Errorf("initialize did not return Mcp-Session-Id")
	}
	var msg jsonrpc.Message
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		return "", fmt.Errorf("initialize decode error: %w", err)
	}
	if msg.Error != nil {
		return "", fmt.Errorf("initialize returned error: %s", msg.Error.Message)
	}
	return sessionID, nil
}

// httpPostE は goroutine 安全な POST（t.Fatal を呼ばない）。
func httpPostE(url string, body string, headers map[string]string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return http.DefaultClient.Do(req)
}

// fetchMetrics は /metrics エンドポイントからテキストを取得する。
func fetchMetrics(t *testing.T, mgmtURL string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mgmtURL+"/metrics", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

// --- Resilience E2E Tests ---

func TestE2EProxyUpstreamCrashMidSession(t *testing.T) {
	upstream := fakeUpstreamMCP(t)

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	// initialize 成功
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	resp := httpPost(t, proxyURL, body, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// upstream を停止
	upstream.Close()

	// 次のリクエストで 502（ハングしない）
	resp2 := httpPost(t, proxyURL, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, nil)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp2.StatusCode, "upstream 停止後は 502 を返すべき")
}

func TestE2EProxyUpstreamSlowResponse(t *testing.T) {
	var delay atomic.Int64

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			d := time.Duration(delay.Load())
			if d > 0 {
				time.Sleep(d)
			}
			body, _ := io.ReadAll(r.Body)
			var msg jsonrpc.Message
			if err := json.Unmarshal(body, &msg); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			resp := jsonrpc.Message{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Result:  json.RawMessage(`{"echo":"` + msg.Method + `"}`),
			}
			if msg.Method == "initialize" {
				w.Header().Set("Mcp-Session-Id", "slow-session")
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// 遅延なし → 200
	resp := httpPost(t, proxyURL, body, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// 遅延 100ms → 200（タイムアウトしない）
	delay.Store(int64(100 * time.Millisecond))
	resp2 := httpPost(t, proxyURL, body, nil)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&msg))
	assert.NotNil(t, msg.Result)
}

func TestE2EProxyConcurrentSessions(t *testing.T) {
	upstream := newMCPMockServer(t, mcpMockOpts{})
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	const numSessions = 10
	var wg sync.WaitGroup
	sessionIDs := make([]string, numSessions)
	errs := make([]error, numSessions)

	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// initialize
			sid, err := mcpInitializeE(proxyURL)
			if err != nil {
				errs[idx] = fmt.Errorf("session %d initialize: %w", idx, err)
				return
			}
			sessionIDs[idx] = sid

			hdrs := map[string]string{"Mcp-Session-Id": sid}

			// tools/list
			listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
			listResp, err := httpPostE(proxyURL, listBody, hdrs)
			if err != nil {
				errs[idx] = fmt.Errorf("session %d tools/list: %w", idx, err)
				return
			}
			defer listResp.Body.Close()
			var listMsg jsonrpc.Message
			if err := json.NewDecoder(listResp.Body).Decode(&listMsg); err != nil {
				errs[idx] = fmt.Errorf("session %d tools/list decode: %w", idx, err)
				return
			}
			if listMsg.Error != nil {
				errs[idx] = fmt.Errorf("session %d tools/list error: %s", idx, listMsg.Error.Message)
				return
			}

			// tools/call (echo)
			callBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}`
			callResp, err := httpPostE(proxyURL, callBody, hdrs)
			if err != nil {
				errs[idx] = fmt.Errorf("session %d tools/call: %w", idx, err)
				return
			}
			defer callResp.Body.Close()
			var callMsg jsonrpc.Message
			if err := json.NewDecoder(callResp.Body).Decode(&callMsg); err != nil {
				errs[idx] = fmt.Errorf("session %d tools/call decode: %w", idx, err)
				return
			}
			if callMsg.Error != nil {
				errs[idx] = fmt.Errorf("session %d tools/call error: %s", idx, callMsg.Error.Message)
				return
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "session %d", i)
	}

	// 全セッション ID がユニーク
	idSet := make(map[string]bool)
	for _, sid := range sessionIDs {
		if sid != "" {
			assert.False(t, idSet[sid], "セッション ID が重複: %s", sid)
			idSet[sid] = true
		}
	}
	assert.Len(t, idSet, numSessions, "全セッション ID がユニークであるべき")
}

func TestE2EProxyGracefulShutdown(t *testing.T) {
	// tools/call のみ 2 秒遅延するカスタムモック
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var msg jsonrpc.Message
			if err := json.Unmarshal(body, &msg); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			if msg.Method == "tools/call" {
				time.Sleep(2 * time.Second)
			}
			resp := jsonrpc.Message{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Result:  json.RawMessage(`{"ok":true}`),
			}
			if msg.Method == "initialize" {
				w.Header().Set("Mcp-Session-Id", "graceful-session")
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	listenAddr := getFreePort(t)
	cmd := exec.Command(binaryPath, "proxy", "--listen", listenAddr, "--upstream", upstream.URL)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	waitForTCP(t, listenAddr, 5*time.Second)
	proxyURL := "http://" + listenAddr

	// goroutine でスロー tools/call リクエストを送信
	type result struct {
		statusCode int
		err        error
	}
	ch := make(chan result, 1)
	go func() {
		callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`
		resp, err := httpPostE(proxyURL, callBody, nil)
		if err != nil {
			ch <- result{err: err}
			return
		}
		resp.Body.Close()
		ch <- result{statusCode: resp.StatusCode}
	}()

	// 500ms 後に SIGINT 送信
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, cmd.Process.Signal(os.Interrupt))

	// リクエスト結果を確認（graceful shutdown で完了するはず）
	res := <-ch
	assert.NoError(t, res.err, "in-flight リクエストは正常完了すべき")
	assert.Equal(t, http.StatusOK, res.statusCode, "in-flight リクエストは 200 を返すべき")

	// プロセスの終了を待つ
	cmd.Wait()
}

func TestE2EProxySessionLifecycleMetrics(t *testing.T) {
	upstream := newMCPMockServer(t, mcpMockOpts{})
	defer upstream.Close()

	mgmtAddr := getFreePort(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: %s
metrics:
  addr: %s
`, upstream.URL, mgmtAddr)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	_, proxyURL := startProxy(t, []string{
		"--config", cfgPath,
	})

	waitForTCP(t, mgmtAddr, 5*time.Second)
	mgmtURL := "http://" + mgmtAddr

	// 2 セッション作成
	sid1 := mcpInitialize(t, proxyURL, nil)
	sid2 := mcpInitialize(t, proxyURL, nil)
	assert.NotEqual(t, sid1, sid2)

	// ゲージが 2 であることを確認
	m := fetchMetrics(t, mgmtURL)
	assert.Contains(t, m, "mcpgw_active_sessions 2", "2 セッション作成後のゲージ")

	// 1 つ DELETE
	delResp := httpDelete(t, proxyURL, map[string]string{"Mcp-Session-Id": sid1})
	delResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, delResp.StatusCode)

	// ゲージが 1 に減少
	m2 := fetchMetrics(t, mgmtURL)
	assert.Contains(t, m2, "mcpgw_active_sessions 1", "1 セッション削除後のゲージ")
}

// --- Performance E2E Tests ---

func TestE2EProxyConcurrentThroughput(t *testing.T) {
	upstream := newMCPMockServer(t, mcpMockOpts{})
	defer upstream.Close()

	_, proxyURL := startProxy(t, []string{
		"--upstream", upstream.URL,
	})

	// セッション確立
	sid := mcpInitialize(t, proxyURL, nil)
	hdrs := map[string]string{"Mcp-Session-Id": sid}

	const numGoroutines = 20
	const numRequests = 10 // 各 goroutine あたり
	total := numGoroutines * numRequests

	var (
		wg        sync.WaitGroup
		successes atomic.Int64
		mu        sync.Mutex
		latencies []time.Duration
	)
	latencies = make([]time.Duration, 0, total)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < numRequests; i++ {
				callBody := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"load"}}}`, i+1)
				start := time.Now()
				resp, err := httpPostE(proxyURL, callBody, hdrs)
				elapsed := time.Since(start)
				if err != nil {
					continue
				}
				var msg jsonrpc.Message
				json.NewDecoder(resp.Body).Decode(&msg)
				resp.Body.Close()
				if msg.Error == nil {
					successes.Add(1)
				}
				mu.Lock()
				latencies = append(latencies, elapsed)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	successRate := float64(successes.Load()) / float64(total) * 100
	t.Logf("throughput: %d/%d succeeded (%.1f%%)", successes.Load(), total, successRate)
	assert.GreaterOrEqual(t, successRate, 95.0, "成功率が 95%% 以上であるべき")

	// 最大レイテンシ確認
	var maxLatency time.Duration
	for _, l := range latencies {
		if l > maxLatency {
			maxLatency = l
		}
	}
	t.Logf("max latency: %v", maxLatency)
	assert.Less(t, maxLatency, 5*time.Second, "最大レイテンシが 5 秒未満であるべき")
}

func TestE2EProxyBurstHandling(t *testing.T) {
	upstream := fakeUpstreamMCP(t)
	defer upstream.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: %s
rate_limit:
  requests_per_second: 1
  burst: 10
`, upstream.URL)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	_, proxyURL := startProxy(t, []string{
		"--config", cfgPath,
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

	// 10 同時送信 → バースト内なのでほぼ全成功
	const burstSize = 10
	var wg sync.WaitGroup
	var burstSuccesses atomic.Int64

	for i := 0; i < burstSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := httpPostE(proxyURL, body, nil)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			var msg jsonrpc.Message
			json.NewDecoder(resp.Body).Decode(&msg)
			if msg.Error == nil {
				burstSuccesses.Add(1)
			}
		}()
	}
	wg.Wait()

	t.Logf("burst: %d/%d succeeded", burstSuccesses.Load(), burstSize)
	assert.GreaterOrEqual(t, burstSuccesses.Load(), int64(burstSize-1), "バースト内はほぼ全成功すべき")

	// 直後の 1 リクエスト → rate limit 超過で -32429
	resp := httpPost(t, proxyURL, body, nil)
	defer resp.Body.Close()
	var msg jsonrpc.Message
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&msg))
	require.NotNil(t, msg.Error, "バースト超過後はエラーを返すべき")
	assert.Equal(t, -32429, msg.Error.Code, "エラーコードは -32429 であるべき")
}

// fakeUpstreamMCPBatch はバッチ JSON-RPC にも対応するフェイク MCP upstream。
func TestE2EProxyReadyz(t *testing.T) {
	upstream := fakeUpstreamMCP(t)

	mgmtAddr := getFreePort(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: %s
metrics:
  addr: %s
`, upstream.URL, mgmtAddr)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	_, _ = startProxy(t, []string{"--config", cfgPath})
	waitForTCP(t, mgmtAddr, 5*time.Second)
	mgmtURL := "http://" + mgmtAddr

	// upstream 起動中 → 200
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mgmtURL+"/readyz", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "ok", body["status"])

	// upstream 停止後 → 503（readiness キャッシュ TTL 超過をポーリングで待つ）
	upstream.Close()
	deadline := time.After(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var lastStatus int
	for {
		select {
		case <-deadline:
			t.Fatalf("readyz が 503 にならなかった (最終ステータス: %d)", lastStatus)
		case <-ticker.C:
			pollCtx, pollCancel := context.WithTimeout(context.Background(), 2*time.Second)
			pollReq, err := http.NewRequestWithContext(pollCtx, http.MethodGet, mgmtURL+"/readyz", nil)
			require.NoError(t, err)
			pollResp, err := http.DefaultClient.Do(pollReq)
			pollCancel()
			if err != nil {
				continue
			}
			lastStatus = pollResp.StatusCode
			pollResp.Body.Close()
			if lastStatus == http.StatusServiceUnavailable {
				return // 成功
			}
		}
	}
}

func TestE2EProxyRequestTimeout(t *testing.T) {
	// 3s 遅延する upstream
	slowUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer slowUpstream.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: %s
transport:
  request_timeout: "1s"
`, slowUpstream.URL)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	_, proxyURL := startProxy(t, []string{"--config", cfgPath})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode, "timeout で 502 が返る")
}

func TestE2EProxyCircuitBreaker(t *testing.T) {
	// 到達不能な upstream（ポートを取得して即閉じ）
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := l.Addr().String()
	l.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgContent := fmt.Sprintf(`
upstream: http://%s
transport:
  request_timeout: "1s"
circuit_breaker:
  max_failures: 3
  timeout: "1s"
`, deadAddr)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	_, proxyURL := startProxy(t, []string{"--config", cfgPath})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// 3 回失敗 → open
	for i := 0; i < 3; i++ {
		resp := httpPost(t, proxyURL, body, nil)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	}

	// 4 回目 → CB open → 503
	resp := httpPost(t, proxyURL, body, nil)
	resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "CB open で 503")

	// timeout 後 → 到達可能な upstream に差し替えはできないが、
	// 復帰確認のため実際の upstream を立ち上げてから待つ
	realUpstream := fakeUpstreamMCP(t)
	defer realUpstream.Close()

	// config を書き換えて再起動はできないので、
	// ここでは timeout 後に half-open → 再度失敗 → open の動作を確認
	time.Sleep(1200 * time.Millisecond)
	resp2 := httpPost(t, proxyURL, body, nil)
	resp2.Body.Close()
	// half-open → 1 リクエスト通過 → dead upstream → 失敗 → open
	assert.Equal(t, http.StatusBadGateway, resp2.StatusCode, "half-open で dead upstream に接続して 502")

	// 再び open → 503
	resp3 := httpPost(t, proxyURL, body, nil)
	resp3.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp3.StatusCode, "再度 open で 503")
}

func fakeUpstreamMCPBatch(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)

			// バッチリクエスト検出
			trimmed := strings.TrimSpace(string(body))
			if len(trimmed) > 0 && trimmed[0] == '[' {
				var msgs []json.RawMessage
				if err := json.Unmarshal(body, &msgs); err != nil {
					http.Error(w, "Bad Request", http.StatusBadRequest)
					return
				}
				var responses []json.RawMessage
				for _, raw := range msgs {
					var msg jsonrpc.Message
					json.Unmarshal(raw, &msg)
					if msg.ID != nil {
						resp := jsonrpc.Message{
							JSONRPC: "2.0",
							ID:      msg.ID,
							Result:  json.RawMessage(`{"echo":"` + msg.Method + `"}`),
						}
						data, _ := json.Marshal(resp)
						responses = append(responses, data)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(responses)
				return
			}

			// 単一リクエスト
			var msg jsonrpc.Message
			if err := json.Unmarshal(body, &msg); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			resp := jsonrpc.Message{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Result:  json.RawMessage(`{"echo":"` + msg.Method + `"}`),
			}
			if msg.Method == "initialize" {
				w.Header().Set("Mcp-Session-Id", "test-session")
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
}
