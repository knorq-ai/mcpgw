package main

import (
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

// fakeUpstreamMCPBatch はバッチ JSON-RPC にも対応するフェイク MCP upstream。
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
