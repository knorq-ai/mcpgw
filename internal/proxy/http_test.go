package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/metrics"
)

// fakeUpstream は httptest.Server で JSON レスポンスを返す MCP upstream をシミュレートする。
func fakeUpstream(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

// newTestProxy はテスト用 HTTPProxy を生成するヘルパー。
func newTestProxy(upstream string, chain *intercept.Chain, audit *intercept.AuditLogger, sessionTTL time.Duration) *HTTPProxy {
	return NewHTTPProxy(HTTPProxyConfig{
		Upstream:   upstream,
		Chain:      chain,
		Audit:      audit,
		SessionTTL: sessionTTL,
	})
}

func TestHTTPProxyPostJSONPassthrough(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msg jsonrpc.Message
		json.Unmarshal(body, &msg)
		resp := jsonrpc.Message{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  json.RawMessage(`{"capabilities":{}}`),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	chain := intercept.NewChain(&passAll{})
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

	var resp jsonrpc.Message
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, json.RawMessage(`1`), resp.ID)
	assert.NotNil(t, resp.Result)
}

func TestHTTPProxyPostBlockedByPolicy(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for blocked requests")
	})

	chain := intercept.NewChain(&blockMethod{method: "tools/call"})
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	reqBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_cmd"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	var resp jsonrpc.Message
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, json.RawMessage(`2`), resp.ID)
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32600, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "blocked")
}

func TestHTTPProxyPostSSEResponse(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		events := []string{
			`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read"}]}}`,
			`{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":1}}`,
			`{"jsonrpc":"2.0","id":2,"result":{}}`,
		}
		for _, ev := range events {
			fmt.Fprintf(w, "data: %s\n\n", ev)
			flusher.Flush()
		}
	})

	chain := intercept.NewChain(&passAll{})
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")

	// SSE レスポンスから3イベント読み取れることを確認
	scanner := NewSSEScanner(strings.NewReader(rec.Body.String()))
	var events []*SSEEvent
	for scanner.Scan() {
		ev := scanner.Event()
		events = append(events, &SSEEvent{Data: ev.Data})
	}
	require.Len(t, events, 3)
}

func TestHTTPProxySSEBlocksOneEvent(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		events := []string{
			`{"jsonrpc":"2.0","id":1,"result":{}}`,
			`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec_cmd"}}`,
			`{"jsonrpc":"2.0","id":3,"result":{}}`,
		}
		for _, ev := range events {
			fmt.Fprintf(w, "data: %s\n\n", ev)
			flusher.Flush()
		}
	})

	// tools/call を S→C 方向でもブロック
	chain := intercept.NewChain(&blockMethod{method: "tools/call"})
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// 3イベント中1つブロック → 2イベントのみクライアントに到達
	scanner := NewSSEScanner(strings.NewReader(rec.Body.String()))
	var events []*SSEEvent
	for scanner.Scan() {
		ev := scanner.Event()
		events = append(events, &SSEEvent{Data: ev.Data})
	}
	assert.Len(t, events, 2)
}

func TestHTTPProxySessionTracking(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Mcp-Session-Id", "test-session-123")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonrpc.Message{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Result:  json.RawMessage(`{}`),
		})
	})

	chain := intercept.NewChain()
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// セッション ID がクライアントに伝播される
	assert.Equal(t, "test-session-123", rec.Header().Get("Mcp-Session-Id"))

	// セッションが追跡されている
	proxy.mu.Lock()
	_, tracked := proxy.sessions["test-session-123"]
	assert.True(t, tracked)
	proxy.mu.Unlock()
}

func TestHTTPProxyDelete(t *testing.T) {
	deleteCalled := false
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalled = true
			assert.Equal(t, "sess-1", r.Header.Get("Mcp-Session-Id"))
			w.WriteHeader(http.StatusOK)
		}
	})

	chain := intercept.NewChain()
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()
	proxy.trackSession("sess-1")

	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", "sess-1")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.True(t, deleteCalled)
	assert.Equal(t, http.StatusOK, rec.Code)

	// セッションが削除されている
	proxy.mu.Lock()
	_, exists := proxy.sessions["sess-1"]
	assert.False(t, exists)
	proxy.mu.Unlock()
}

func TestHTTPProxyMethodNotAllowed(t *testing.T) {
	chain := intercept.NewChain()
	proxy := newTestProxy("http://localhost:1", chain, nil, 0)
	defer proxy.Close()

	req := httptest.NewRequest(http.MethodPut, "/mcp", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestHTTPProxyUpstreamDown(t *testing.T) {
	chain := intercept.NewChain()
	// 接続できないアドレスを指定
	proxy := newTestProxy("http://127.0.0.1:1", chain, nil, 0)
	defer proxy.Close()

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestHTTPProxyGetSSEStream(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		fmt.Fprintf(w, "data: %s\n\n", `{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`)
		flusher.Flush()
	})

	chain := intercept.NewChain()
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", "text/event-stream")
	// httptest.NewRecorder を使うとストリーミングが同期的に完了する
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	scanner := NewSSEScanner(strings.NewReader(rec.Body.String()))
	require.True(t, scanner.Scan())
	assert.Contains(t, scanner.Event().Data, "notifications/progress")
}

func TestHTTPProxyContextCancellation(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonrpc.Message{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Result:  json.RawMessage(`{}`),
		})
	})

	chain := intercept.NewChain()
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 即座にキャンセル

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)
	// キャンセル済みコンテキストでは upstream への接続が失敗する
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestHTTPProxySessionTTLExpiry(t *testing.T) {
	chain := intercept.NewChain()
	proxy := newTestProxy("http://localhost:1", chain, nil, 1*time.Minute)
	defer proxy.Close()

	// セッションを追跡
	proxy.trackSession("sess-old")

	// 直後 → セッションは存在する
	proxy.mu.Lock()
	_, exists := proxy.sessions["sess-old"]
	assert.True(t, exists)
	proxy.mu.Unlock()

	// タイムスタンプを古くして cleanup を手動実行
	proxy.mu.Lock()
	proxy.sessions["sess-old"] = time.Now().Add(-2 * time.Minute)
	proxy.mu.Unlock()

	proxy.cleanupSessions()

	proxy.mu.Lock()
	_, exists = proxy.sessions["sess-old"]
	assert.False(t, exists, "TTL 超過セッションは削除されるべき")
	proxy.mu.Unlock()
}

func TestHTTPProxySessionTTLRefresh(t *testing.T) {
	chain := intercept.NewChain()
	proxy := newTestProxy("http://localhost:1", chain, nil, 5*time.Minute)
	defer proxy.Close()

	proxy.trackSession("sess-active")
	time.Sleep(10 * time.Millisecond)
	proxy.trackSession("sess-active") // タイムスタンプ更新

	proxy.mu.Lock()
	ts := proxy.sessions["sess-active"]
	proxy.mu.Unlock()

	// 最終アクセス時刻が最近であることを確認
	assert.WithinDuration(t, time.Now(), ts, 1*time.Second)
}

func TestHTTPProxyCloseStopsGoroutine(t *testing.T) {
	chain := intercept.NewChain()
	proxy := newTestProxy("http://localhost:1", chain, nil, 0)

	// Close が goroutine を停止し、ブロックしないことを確認
	done := make(chan struct{})
	go func() {
		proxy.Close()
		close(done)
	}()
	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Close がタイムアウトした")
	}
}

func TestHTTPProxyRequestID(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		// upstream がリクエスト ID を受け取っていることを確認
		reqID := r.Header.Get("X-Request-Id")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonrpc.Message{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Result:  json.RawMessage(fmt.Sprintf(`{"req_id":%q}`, reqID)),
		})
	})

	chain := intercept.NewChain()
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	// クライアントが X-Request-Id を指定した場合
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("X-Request-Id", "custom-id-123")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, "custom-id-123", rec.Header().Get("X-Request-Id"))

	// クライアントが X-Request-Id を指定しなかった場合 — 自動生成
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	rec2 := httptest.NewRecorder()

	proxy.ServeHTTP(rec2, req2)

	generatedID := rec2.Header().Get("X-Request-Id")
	assert.NotEmpty(t, generatedID)
	assert.Len(t, generatedID, 32) // 16 bytes hex = 32 chars
}

func TestHTTPProxyBatchPost(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msgs []json.RawMessage
		if err := json.Unmarshal(body, &msgs); err != nil {
			// 単一メッセージの場合
			var msg jsonrpc.Message
			json.Unmarshal(body, &msg)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jsonrpc.Message{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Result:  json.RawMessage(`{}`),
			})
			return
		}
		// バッチレスポンス
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
	})

	chain := intercept.NewChain(&passAll{})
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	// バッチリクエスト
	batchBody := `[
		{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
		{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(batchBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

	var responses []json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &responses))
	assert.Len(t, responses, 2)
}

func TestHTTPProxyBatchPostWithBlock(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msgs []json.RawMessage
		json.Unmarshal(body, &msgs)
		var responses []json.RawMessage
		for _, raw := range msgs {
			var msg jsonrpc.Message
			json.Unmarshal(raw, &msg)
			if msg.ID != nil {
				resp := jsonrpc.Message{
					JSONRPC: "2.0",
					ID:      msg.ID,
					Result:  json.RawMessage(`{}`),
				}
				data, _ := json.Marshal(resp)
				responses = append(responses, data)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responses)
	})

	chain := intercept.NewChain(&blockMethod{method: "tools/call"})
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	// 3メッセージ中 1 つがブロック対象
	batchBody := `[
		{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_cmd"}},
		{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(batchBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	var responses []json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &responses))
	// エラーレスポンス 1 + upstream レスポンス 2 = 3
	assert.Len(t, responses, 3)

	// ブロックされたメッセージのエラーレスポンスを探す
	foundBlock := false
	for _, raw := range responses {
		var msg jsonrpc.Message
		json.Unmarshal(raw, &msg)
		if msg.Error != nil && msg.Error.Code == -32600 {
			foundBlock = true
			assert.Contains(t, msg.Error.Message, "blocked")
		}
	}
	assert.True(t, foundBlock, "ブロックされたメッセージのエラーレスポンスが存在すべき")
}

func TestHTTPProxyBatchPostAllBlocked(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when all messages are blocked")
	})

	chain := intercept.NewChain(&blockMethod{method: "tools/call"})
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	batchBody := `[
		{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},
		{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"b"}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(batchBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	var responses []json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &responses))
	assert.Len(t, responses, 2)

	for _, raw := range responses {
		var msg jsonrpc.Message
		json.Unmarshal(raw, &msg)
		require.NotNil(t, msg.Error)
		assert.Equal(t, -32600, msg.Error.Code)
	}
}

func TestTrackSessionGaugeAccuracy(t *testing.T) {
	chain := intercept.NewChain()
	proxy := newTestProxy("http://localhost:1", chain, nil, 0)
	defer proxy.Close()

	metrics.ActiveSessions.Set(0)

	proxy.trackSession("A")
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.ActiveSessions))

	// refresh — gauge は変わらない
	proxy.trackSession("A")
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.ActiveSessions))

	proxy.trackSession("B")
	assert.Equal(t, float64(2), testutil.ToFloat64(metrics.ActiveSessions))
}

func TestCleanupSessionsDecrementsGauge(t *testing.T) {
	chain := intercept.NewChain()
	proxy := newTestProxy("http://localhost:1", chain, nil, 1*time.Minute)
	defer proxy.Close()

	metrics.ActiveSessions.Set(0)

	proxy.trackSession("s1")
	proxy.trackSession("s2")
	proxy.trackSession("s3")
	assert.Equal(t, float64(3), testutil.ToFloat64(metrics.ActiveSessions))

	// s1, s2 の TTL を超過させる
	proxy.mu.Lock()
	proxy.sessions["s1"] = time.Now().Add(-2 * time.Minute)
	proxy.sessions["s2"] = time.Now().Add(-2 * time.Minute)
	proxy.mu.Unlock()

	proxy.cleanupSessions()
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.ActiveSessions))
}

func TestRemoveSessionGauge(t *testing.T) {
	chain := intercept.NewChain()
	proxy := newTestProxy("http://localhost:1", chain, nil, 0)
	defer proxy.Close()

	metrics.ActiveSessions.Set(0)

	proxy.trackSession("X")
	assert.Equal(t, float64(1), testutil.ToFloat64(metrics.ActiveSessions))

	proxy.removeSession("X")
	assert.Equal(t, float64(0), testutil.ToFloat64(metrics.ActiveSessions))

	// 二重削除で -1 にならないことを確認
	proxy.removeSession("X")
	assert.Equal(t, float64(0), testutil.ToFloat64(metrics.ActiveSessions))
}

func TestHTTPProxyRequestIDTooLong(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonrpc.Message{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Result:  json.RawMessage(`{}`),
		})
	})

	chain := intercept.NewChain()
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(reqBody))
	req.Header.Set("X-Request-Id", strings.Repeat("a", 200))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// 長すぎるリクエスト ID は再生成される（16 バイト hex = 32 文字）
	generatedID := rec.Header().Get("X-Request-Id")
	assert.Len(t, generatedID, 32)
}

func TestHTTPProxyBatchEmptyArray(t *testing.T) {
	upstream := fakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for empty batch")
	})

	chain := intercept.NewChain()
	proxy := newTestProxy(upstream.URL, chain, nil, 0)
	defer proxy.Close()

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`[]`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
