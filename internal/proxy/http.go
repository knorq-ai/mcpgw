package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/metrics"
)

// maxBodySize はリクエスト/レスポンスボディの最大サイズ（10MB）。
// 超過時は切り詰められ、パース失敗として fail-open で処理される。
const maxBodySize = 10 * 1024 * 1024

// maxBatchSize はバッチ JSON-RPC リクエストの最大メッセージ数。
// 大量メッセージによる CPU・メモリ消費の増幅攻撃を防止する。
const maxBatchSize = 100

// HTTPProxyConfig は HTTPProxy の設定。
type HTTPProxyConfig struct {
	Upstream            string
	Chain               *intercept.Chain
	Audit               *intercept.AuditLogger
	SessionTTL          time.Duration
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
}

// HTTPProxy は MCP Streamable HTTP トランスポートのリバースプロキシ。
// POST/GET/DELETE を単一エンドポイントで処理し、interceptor chain と audit logger を適用する。
type HTTPProxy struct {
	upstream string
	chain    *intercept.Chain
	audit    *intercept.AuditLogger
	client   *http.Client // ResponseHeaderTimeout で応答開始を制限、ボディ読み取りは無制限
	mu       sync.Mutex
	sessions map[string]time.Time // sid → 最終アクセス時刻
	ttl      time.Duration
	stopCh   chan struct{}
	stopped  chan struct{}
}

// NewHTTPProxy は HTTPProxy を生成する。
func NewHTTPProxy(cfg HTTPProxyConfig) *HTTPProxy {
	sessionTTL := cfg.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = 30 * time.Minute
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 100
	}
	maxIdlePerHost := cfg.MaxIdleConnsPerHost
	if maxIdlePerHost <= 0 {
		maxIdlePerHost = 10
	}
	idleTimeout := cfg.IdleConnTimeout
	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}

	p := &HTTPProxy{
		upstream: strings.TrimRight(cfg.Upstream, "/"),
		chain:    cfg.Chain,
		audit:    cfg.Audit,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:          maxIdle,
				MaxIdleConnsPerHost:   maxIdlePerHost,
				IdleConnTimeout:       idleTimeout,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		},
		sessions: make(map[string]time.Time),
		ttl:      sessionTTL,
		stopCh:   make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	go p.cleanupLoop()
	return p
}

// Close は cleanup goroutine を停止する。
func (p *HTTPProxy) Close() {
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
	<-p.stopped
}

// cleanupLoop は 1 分間隔で TTL 超過セッションを削除する。
func (p *HTTPProxy) cleanupLoop() {
	defer close(p.stopped)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.cleanupSessions()
		}
	}
}

func (p *HTTPProxy) cleanupSessions() {
	p.mu.Lock()
	defer p.mu.Unlock()
	cutoff := time.Now().Add(-p.ttl)
	for sid, lastAccess := range p.sessions {
		if lastAccess.Before(cutoff) {
			delete(p.sessions, sid)
			metrics.ActiveSessions.Dec()
		}
	}
}

// generateRequestID は 16 バイトのランダム ID を生成する。
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

// isValidRequestID はリクエスト ID のバリデーションを行う。
// 空文字、128 文字超過、制御文字を含む場合は false を返す。
func isValidRequestID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// ServeHTTP は HTTP リクエストをメソッドに応じて振り分ける。
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// リクエスト ID の取得または生成
	reqID := r.Header.Get("X-Request-Id")
	if !isValidRequestID(reqID) {
		reqID = generateRequestID()
	}
	w.Header().Set("X-Request-Id", reqID)
	ctx := intercept.WithRequestID(r.Context(), reqID)
	r = r.WithContext(ctx)

	switch r.Method {
	case http.MethodPost:
		p.handlePost(w, r)
	case http.MethodGet:
		p.handleGet(w, r)
	case http.MethodDelete:
		p.handleDelete(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}

	metrics.RequestDuration.WithLabelValues(r.Method).Observe(time.Since(start).Seconds())
}

// handlePost は JSON-RPC メッセージを含む POST リクエストを処理する。
func (p *HTTPProxy) handlePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// バッチリクエスト検出
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		p.handleBatchPost(w, r, trimmed)
		return
	}

	// JSON-RPC メッセージをパース
	var msg jsonrpc.Message
	var parsed *jsonrpc.Message
	if err := json.Unmarshal(body, &msg); err == nil {
		parsed = &msg
	}

	// interceptor chain を実行
	result := p.chain.Process(r.Context(), intercept.DirClientToServer, parsed, body)

	// 監査ログ
	if p.audit != nil {
		p.audit.Log(r.Context(), intercept.DirClientToServer, parsed, body, result)
	}

	method := ""
	action := "pass"
	if parsed != nil {
		method = parsed.Method
	}

	// ブロック → JSON-RPC エラーレスポンスを返す
	if result.Action == intercept.ActionBlock {
		action = "block"
		metrics.RequestsTotal.WithLabelValues(method, action).Inc()
		if parsed != nil && parsed.IsRequest() {
			code := result.ErrorCode
			if code == 0 {
				code = -32600
			}
			w.Header().Set("Content-Type", "application/json")
			errResp := buildErrorResponse(parsed.ID, code, result.Reason)
			data, _ := json.Marshal(errResp)
			w.Write(data)
		} else {
			// リクエスト以外のブロック（通知等）— 空レスポンス
			w.WriteHeader(http.StatusAccepted)
		}
		return
	}

	metrics.RequestsTotal.WithLabelValues(method, action).Inc()

	// upstream に転送
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.upstream, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json, text/event-stream")

	setProxyHeaders(upReq, r)

	// Mcp-Session-Id を伝播
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}

	// X-Request-Id を upstream に伝播
	if reqID := intercept.RequestIDFromContext(r.Context()); reqID != "" {
		upReq.Header.Set("X-Request-Id", reqID)
	}

	resp, err := p.client.Do(upReq)
	if err != nil {
		metrics.UpstreamErrors.Inc()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Mcp-Session-Id を追跡
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		p.trackSession(sid)
		w.Header().Set("Mcp-Session-Id", sid)
	}

	ct := resp.Header.Get("Content-Type")

	// SSE レスポンスの場合はストリーム傍受
	if strings.HasPrefix(ct, "text/event-stream") {
		p.streamSSE(r.Context(), w, resp.Body)
		return
	}

	// JSON レスポンスの場合
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		metrics.UpstreamErrors.Inc()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// S→C interceptor chain を実行
	var respMsg jsonrpc.Message
	var respParsed *jsonrpc.Message
	if err := json.Unmarshal(respBody, &respMsg); err == nil {
		respParsed = &respMsg
	}

	respResult := p.chain.Process(r.Context(), intercept.DirServerToClient, respParsed, respBody)
	if p.audit != nil {
		p.audit.Log(r.Context(), intercept.DirServerToClient, respParsed, respBody, respResult)
	}

	if respResult.Action == intercept.ActionBlock {
		// S→C ブロック — クライアントに JSON-RPC エラーを返す
		if respParsed != nil && respParsed.IsResponse() {
			w.Header().Set("Content-Type", "application/json")
			errResp := buildErrorResponse(respParsed.ID, -32603, "blocked by policy")
			data, _ := json.Marshal(errResp)
			w.Write(data)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		return
	}

	w.Header().Set("Content-Type", ct)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleBatchPost はバッチ JSON-RPC リクエストを処理する。
func (p *HTTPProxy) handleBatchPost(w http.ResponseWriter, r *http.Request, body []byte) {
	var rawMessages []json.RawMessage
	if err := json.Unmarshal(body, &rawMessages); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if len(rawMessages) == 0 || len(rawMessages) > maxBatchSize {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 各メッセージを C→S interceptor chain で処理
	var passMessages []json.RawMessage
	var errorResponses []json.RawMessage

	for _, raw := range rawMessages {
		var msg jsonrpc.Message
		var parsed *jsonrpc.Message
		if err := json.Unmarshal(raw, &msg); err == nil {
			parsed = &msg
		}

		result := p.chain.Process(r.Context(), intercept.DirClientToServer, parsed, raw)
		if p.audit != nil {
			p.audit.Log(r.Context(), intercept.DirClientToServer, parsed, raw, result)
		}

		method := ""
		if parsed != nil {
			method = parsed.Method
		}

		if result.Action == intercept.ActionBlock {
			metrics.RequestsTotal.WithLabelValues(method, "block").Inc()
			if parsed != nil && parsed.IsRequest() {
				code := result.ErrorCode
				if code == 0 {
					code = -32600
				}
				errResp := buildErrorResponse(parsed.ID, code, result.Reason)
				data, _ := json.Marshal(errResp)
				errorResponses = append(errorResponses, data)
			}
			// 通知のブロックはサイレントドロップ
		} else {
			metrics.RequestsTotal.WithLabelValues(method, "pass").Inc()
			passMessages = append(passMessages, raw)
		}
	}

	// 全ブロック時は upstream を呼ばずエラーレスポンスのみ返却
	if len(passMessages) == 0 {
		if len(errorResponses) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		result := marshalBatchResponse(errorResponses)
		w.Write(result)
		return
	}

	// 非ブロックメッセージを JSON 配列として upstream に転送
	batchBody, err := json.Marshal(passMessages)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.upstream, bytes.NewReader(batchBody))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json")
	setProxyHeaders(upReq, r)
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}
	if reqID := intercept.RequestIDFromContext(r.Context()); reqID != "" {
		upReq.Header.Set("X-Request-Id", reqID)
	}

	resp, err := p.client.Do(upReq)
	if err != nil {
		metrics.UpstreamErrors.Inc()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		p.trackSession(sid)
		w.Header().Set("Mcp-Session-Id", sid)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		metrics.UpstreamErrors.Inc()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// upstream レスポンス配列をパース
	var upstreamResponses []json.RawMessage
	if err := json.Unmarshal(respBody, &upstreamResponses); err != nil {
		// 配列でない場合（単一レスポンス or 非 JSON）— そのまま返す
		// エラーレスポンスがあればマージ
		if len(errorResponses) > 0 {
			// 単一レスポンスをエラーレスポンスとマージ
			var allResponses []json.RawMessage
			allResponses = append(allResponses, errorResponses...)
			allResponses = append(allResponses, respBody)
			w.Header().Set("Content-Type", "application/json")
			w.Write(marshalBatchResponse(allResponses))
			return
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	// 各レスポンスに S→C interceptor chain を実行
	var processedResponses []json.RawMessage
	for _, raw := range upstreamResponses {
		var msg jsonrpc.Message
		var parsed *jsonrpc.Message
		if err := json.Unmarshal(raw, &msg); err == nil {
			parsed = &msg
		}

		result := p.chain.Process(r.Context(), intercept.DirServerToClient, parsed, raw)
		if p.audit != nil {
			p.audit.Log(r.Context(), intercept.DirServerToClient, parsed, raw, result)
		}

		if result.Action == intercept.ActionBlock {
			if parsed != nil && parsed.IsResponse() {
				errResp := buildErrorResponse(parsed.ID, -32603, "blocked by policy")
				data, _ := json.Marshal(errResp)
				processedResponses = append(processedResponses, data)
			}
		} else {
			processedResponses = append(processedResponses, raw)
		}
	}

	// エラーレスポンスとマージ
	var allResponses []json.RawMessage
	allResponses = append(allResponses, errorResponses...)
	allResponses = append(allResponses, processedResponses...)

	w.Header().Set("Content-Type", "application/json")
	w.Write(marshalBatchResponse(allResponses))
}

// marshalBatchResponse はレスポンス配列を JSON 配列にマーシャルする。
func marshalBatchResponse(responses []json.RawMessage) []byte {
	data, _ := json.Marshal(responses)
	return data
}

// streamSSE は upstream からの SSE ストリームを傍受しながらクライアントに転送する。
func (p *HTTPProxy) streamSSE(ctx context.Context, w http.ResponseWriter, body io.ReadCloser) {
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

	scanner := NewSSEScanner(body)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}

		ev := scanner.Event()

		// Data から JSON-RPC メッセージを抽出して interceptor chain を実行
		var msg jsonrpc.Message
		var parsed *jsonrpc.Message
		raw := []byte(ev.Data)
		if err := json.Unmarshal(raw, &msg); err == nil {
			parsed = &msg
		}

		result := p.chain.Process(ctx, intercept.DirServerToClient, parsed, raw)
		if p.audit != nil {
			p.audit.Log(ctx, intercept.DirServerToClient, parsed, raw, result)
		}

		if result.Action == intercept.ActionBlock {
			// S→C ブロック — イベントをドロップしてログ出力
			slog.Warn("SSE event blocked", "reason", result.Reason)
			continue
		}

		// クライアントに転送
		formatted := FormatSSEEvent(ev)
		if _, err := w.Write(formatted); err != nil {
			slog.Error("SSE write error", "error", err)
			return
		}
		flusher.Flush()
	}
}

// setProxyHeaders は upstream リクエストにプロキシヘッダを設定する。
func setProxyHeaders(upReq *http.Request, r *http.Request) {
	if clientIP := r.RemoteAddr; clientIP != "" {
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			upReq.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			upReq.Header.Set("X-Forwarded-For", clientIP)
		}
	}
	if r.TLS != nil {
		upReq.Header.Set("X-Forwarded-Proto", "https")
	} else {
		upReq.Header.Set("X-Forwarded-Proto", "http")
	}
}

// handleGet は SSE ストリーム接続を処理する。
func (p *HTTPProxy) handleGet(w http.ResponseWriter, r *http.Request) {
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.upstream, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	upReq.Header.Set("Accept", "text/event-stream")
	setProxyHeaders(upReq, r)

	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}
	if reqID := intercept.RequestIDFromContext(r.Context()); reqID != "" {
		upReq.Header.Set("X-Request-Id", reqID)
	}

	resp, err := p.client.Do(upReq)
	if err != nil {
		metrics.UpstreamErrors.Inc()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		w.Header().Set("Mcp-Session-Id", sid)
	}

	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		p.streamSSE(r.Context(), w, resp.Body)
		return
	}

	// 非 SSE レスポンス → そのまま転送
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleDelete はセッション終了リクエストを処理する。
func (p *HTTPProxy) handleDelete(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("Mcp-Session-Id")

	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, p.upstream, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	setProxyHeaders(upReq, r)
	if sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}
	if reqID := intercept.RequestIDFromContext(r.Context()); reqID != "" {
		upReq.Header.Set("X-Request-Id", reqID)
	}

	resp, err := p.client.Do(upReq)
	if err != nil {
		metrics.UpstreamErrors.Inc()
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// セッション追跡から削除
	if sid != "" {
		p.removeSession(sid)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *HTTPProxy) trackSession(sid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, exists := p.sessions[sid]
	p.sessions[sid] = time.Now()
	if !exists {
		metrics.ActiveSessions.Inc()
	}
}

func (p *HTTPProxy) removeSession(sid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.sessions[sid]; ok {
		delete(p.sessions, sid)
		metrics.ActiveSessions.Dec()
	}
}
