package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/metrics"
	"github.com/knorq-ai/mcpgw/internal/routing"
)

// maxBodySize はリクエスト/レスポンスボディの最大サイズ（10MB）。
// 超過時は切り詰められ、パース失敗として fail-open で処理される。
const maxBodySize = 10 * 1024 * 1024

// mustMarshalMessage は jsonrpc.Message を JSON バイト列にマーシャルする。
// 失敗時はログ出力し、フォールバックの JSON エラーレスポンスを返す。
func mustMarshalMessage(msg *jsonrpc.Message) []byte {
	data, err := json.Marshal(msg)
	if err != nil {
		slog.Error("json.Marshal failed for JSON-RPC message", "error", err)
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"}}`)
	}
	return data
}

// maxBatchSize はバッチ JSON-RPC リクエストの最大メッセージ数。
// 大量メッセージによる CPU・メモリ消費の増幅攻撃を防止する。
const maxBatchSize = 100

// HTTPProxyConfig は HTTPProxy の設定。
type HTTPProxyConfig struct {
	Upstream            string
	Router              *routing.Router // nil の場合は Upstream を使用
	Chain               *intercept.Chain
	Audit               *intercept.AuditLogger
	SessionTTL          time.Duration
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
	RequestTimeout      time.Duration
	SSEIdleTimeout      time.Duration
	DrainTimeout        time.Duration
	CircuitBreaker      CircuitBreakerConfig
}

// CircuitBreakerConfig はサーキットブレーカーの設定（proxy パッケージ内用）。
type CircuitBreakerConfig struct {
	MaxFailures int
	Timeout     time.Duration
}

// HTTPProxy は MCP Streamable HTTP トランスポートのリバースプロキシ。
// POST/GET/DELETE を単一エンドポイントで処理し、interceptor chain と audit logger を適用する。
type HTTPProxy struct {
	upstream       string
	router         *routing.Router     // ツール名ベースのルーティング（nil = 単一 upstream）
	chain          *intercept.Chain
	audit          *intercept.AuditLogger
	client         *http.Client        // ResponseHeaderTimeout で応答開始を制限、ボディ読み取りは無制限
	mu             sync.Mutex
	sessions       map[string]time.Time // sid → 最終アクセス時刻
	ttl            time.Duration
	requestTimeout time.Duration
	sseIdleTimeout time.Duration
	drainTimeout   time.Duration
	draining       atomic.Bool          // drain フェーズ中フラグ
	drainWg        sync.WaitGroup       // アクティブな SSE ストリーム数を追跡
	cbs            map[string]*circuitBreaker // upstream URL → サーキットブレーカー
	cb             *circuitBreaker      // デフォルト CB（後方互換）
	readyClient    *http.Client                  // readiness probe 専用（本番接続プールと分離）
	readySnap      atomic.Pointer[readySnapshot] // UpstreamReady キャッシュ
	readyMu        sync.Mutex                    // UpstreamReady の同時 HEAD リクエストを防止
	stopCh         chan struct{}
	stopped        chan struct{}
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
	requestTimeout := cfg.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 60 * time.Second
	}
	sseIdleTimeout := cfg.SSEIdleTimeout
	if sseIdleTimeout <= 0 {
		sseIdleTimeout = 5 * time.Minute
	}

	drainTimeout := cfg.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = 30 * time.Second
	}

	// サーキットブレーカーの構築（per-upstream）
	var defaultCB *circuitBreaker
	cbs := make(map[string]*circuitBreaker)
	if cfg.CircuitBreaker.MaxFailures > 0 {
		defaultCB = newCircuitBreaker(cfg.CircuitBreaker.MaxFailures, cfg.CircuitBreaker.Timeout)
		upstreamURL := strings.TrimRight(cfg.Upstream, "/")
		cbs[upstreamURL] = defaultCB
		// Router が設定されている場合、各 upstream 用の CB も作成
		if cfg.Router != nil {
			for _, u := range cfg.Router.Upstreams() {
				if _, ok := cbs[u]; !ok {
					cbs[u] = newCircuitBreaker(cfg.CircuitBreaker.MaxFailures, cfg.CircuitBreaker.Timeout)
				}
			}
		}
	}

	p := &HTTPProxy{
		upstream: strings.TrimRight(cfg.Upstream, "/"),
		router:   cfg.Router,
		chain:    cfg.Chain,
		audit:    cfg.Audit,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:          maxIdle,
				MaxIdleConnsPerHost:   maxIdlePerHost,
				IdleConnTimeout:       idleTimeout,
				ResponseHeaderTimeout: requestTimeout,
			},
		},
		sessions:       make(map[string]time.Time),
		ttl:            sessionTTL,
		requestTimeout: requestTimeout,
		sseIdleTimeout: sseIdleTimeout,
		drainTimeout:   drainTimeout,
		cbs:            cbs,
		cb:             defaultCB,
		readyClient: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    1,
				IdleConnTimeout: 10 * time.Second,
			},
		},
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
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

// resolveUpstream はメソッドとパラメータから転送先 upstream を決定する。
func (p *HTTPProxy) resolveUpstream(method string, params json.RawMessage) string {
	if p.router != nil {
		return p.router.Resolve(method, params)
	}
	return p.upstream
}

// cbFor は指定 upstream URL に対応するサーキットブレーカーを返す。
// URL のスキーム+ホスト部分でマッチングする。
func (p *HTTPProxy) cbFor(upstreamURL string) *circuitBreaker {
	// 末尾スラッシュやパスを除去してベース URL でマッチ
	base := strings.TrimRight(upstreamURL, "/")
	if cb, ok := p.cbs[base]; ok {
		return cb
	}
	return p.cb
}

// Draining は drain 中かどうかを返す。
func (p *HTTPProxy) Draining() bool {
	return p.draining.Load()
}

// Drain は drain フェーズを開始し、既存の SSE ストリームの完了を待つ。
// drainTimeout を超過した場合はタイムアウトして戻る。
func (p *HTTPProxy) Drain() {
	p.draining.Store(true)
	slog.Info("drain started, waiting for active streams", "timeout", p.drainTimeout)
	done := make(chan struct{})
	go func() {
		p.drainWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		slog.Info("drain complete, all streams finished")
	case <-time.After(p.drainTimeout):
		slog.Warn("drain timeout exceeded, proceeding with shutdown")
	}
}

// doUpstream はサーキットブレーカーを経由して upstream にリクエストを送信する。
// 失敗時はエラーレスポンスをクライアントに書き込み nil を返す。
func (p *HTTPProxy) doUpstream(w http.ResponseWriter, req *http.Request) *http.Response {
	upBase := req.URL.Scheme + "://" + req.URL.Host
	cb := p.cbFor(upBase)
	allowed, state := cb.Allow()
	if !allowed {
		if state == stateOpen {
			metrics.CircuitBreakerTrips.Inc()
		}
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return nil
	}
	resp, err := p.client.Do(req)
	if err != nil {
		// クライアント切断による失敗は upstream 障害としてカウントしない
		if req.Context().Err() == nil {
			cb.RecordFailure()
			metrics.UpstreamErrors.Inc()
		}
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return nil
	}
	cb.RecordSuccess()
	return resp
}

// readyCacheTTL は UpstreamReady キャッシュの有効期間。
const readyCacheTTL = 2 * time.Second

// readySnapshot は UpstreamReady の結果と時刻をまとめたアトミックスナップショット。
type readySnapshot struct {
	ready bool
	at    time.Time
}

// UpstreamReady は upstream への到達性を確認する。
// 結果を 2 秒間キャッシュし、readiness probe による upstream への負荷を軽減する。
// 同時呼び出しは readyMu で直列化し、thundering herd を防止する。
// 本番接続プールとは分離した readyClient を使用する。
func (p *HTTPProxy) UpstreamReady() bool {
	if snap := p.readySnap.Load(); snap != nil && time.Since(snap.at) < readyCacheTTL {
		return snap.ready
	}

	// TryLock で排他 — 取得できなかった場合はキャッシュ（stale でも）を返す
	if !p.readyMu.TryLock() {
		if snap := p.readySnap.Load(); snap != nil {
			return snap.ready
		}
		return true // キャッシュ未生成時は楽観的に true
	}
	defer p.readyMu.Unlock()

	// ロック取得後にキャッシュを再確認（他の goroutine が更新済みかもしれない）
	if snap := p.readySnap.Load(); snap != nil && time.Since(snap.at) < readyCacheTTL {
		return snap.ready
	}

	req, err := http.NewRequest(http.MethodHead, p.upstream, nil)
	if err != nil {
		p.readySnap.Store(&readySnapshot{ready: false, at: time.Now()})
		return false
	}
	resp, err := p.readyClient.Do(req)
	if err != nil {
		p.readySnap.Store(&readySnapshot{ready: false, at: time.Now()})
		return false
	}
	resp.Body.Close()
	p.readySnap.Store(&readySnapshot{ready: true, at: time.Now()})
	return true
}

// ActiveSessionCount はアクティブセッション数を返す。
func (p *HTTPProxy) ActiveSessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

// Upstream は upstream URL を返す。
func (p *HTTPProxy) Upstream() string {
	return p.upstream
}

// CircuitBreakerState はサーキットブレーカーの現在状態を文字列で返す。
func (p *HTTPProxy) CircuitBreakerState() string {
	return p.cb.State()
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
	// drain 中は新規リクエストを拒否
	if p.draining.Load() {
		http.Error(w, "Service Unavailable (draining)", http.StatusServiceUnavailable)
		return
	}

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
			w.Write(mustMarshalMessage(errResp))
		} else {
			// リクエスト以外のブロック（通知等）— 空レスポンス
			w.WriteHeader(http.StatusAccepted)
		}
		return
	}

	// ActionRedact の場合はリダクション済みボディを使用する
	if result.Action == intercept.ActionRedact && result.RedactedBody != nil {
		action = "redact"
		body = result.RedactedBody
	}

	metrics.RequestsTotal.WithLabelValues(method, action).Inc()

	// upstream に転送（ルーティング解決）
	// POST は SSE レスポンスの可能性があるため context timeout は使わず、
	// Transport.ResponseHeaderTimeout でヘッダ応答のタイムアウトを制御する。
	targetUpstream := p.resolveUpstream(method, nil)
	if parsed != nil {
		targetUpstream = p.resolveUpstream(parsed.Method, parsed.Params)
	}
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetUpstream, bytes.NewReader(body))
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

	resp := p.doUpstream(w, upReq)
	if resp == nil {
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

	// JSON レスポンスの場合 — タイムアウト付きで読み取り。
	// ResponseHeaderTimeout はヘッダ到着のみを制御するため、
	// ボディ読み取りには別途 requestTimeout を適用して slow-body 攻撃を防ぐ。
	readCtx, readCancel := context.WithTimeout(r.Context(), p.requestTimeout)
	defer readCancel()
	respBody, err := io.ReadAll(io.LimitReader(newContextReader(readCtx, resp.Body), maxBodySize))
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
			w.Write(mustMarshalMessage(errResp))
		} else {
			w.WriteHeader(http.StatusOK)
		}
		return
	}

	// ActionRedact の場合はリダクション済みボディを使用する
	if respResult.Action == intercept.ActionRedact && respResult.RedactedBody != nil {
		respBody = respResult.RedactedBody
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
				errorResponses = append(errorResponses, mustMarshalMessage(errResp))
			}
			// 通知のブロックはサイレントドロップ
		} else {
			action := "pass"
			forwardRaw := raw
			if result.Action == intercept.ActionRedact && result.RedactedBody != nil {
				action = "redact"
				forwardRaw = json.RawMessage(result.RedactedBody)
			}
			metrics.RequestsTotal.WithLabelValues(method, action).Inc()
			passMessages = append(passMessages, forwardRaw)
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

	// バッチは SSE レスポンスにならないため、context timeout で全体（接続+転送）のタイムアウトを制御する。
	// 単一 POST は SSE の可能性があるため context timeout を使わず ResponseHeaderTimeout に任せる。
	// Transport の ResponseHeaderTimeout（= requestTimeout）も存在するが、context deadline の方が
	// 先に発火するため実質的に context timeout が支配する。
	batchCtx, batchCancel := context.WithTimeout(r.Context(), p.requestTimeout)
	defer batchCancel()

	upReq, err := http.NewRequestWithContext(batchCtx, http.MethodPost, p.upstream, bytes.NewReader(batchBody))
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

	resp := p.doUpstream(w, upReq)
	if resp == nil {
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
				processedResponses = append(processedResponses, mustMarshalMessage(errResp))
			}
		} else if result.Action == intercept.ActionRedact && result.RedactedBody != nil {
			processedResponses = append(processedResponses, json.RawMessage(result.RedactedBody))
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
	data, err := json.Marshal(responses)
	if err != nil {
		slog.Error("json.Marshal failed for batch response", "error", err)
		return []byte(`[]`)
	}
	return data
}

// streamSSE は upstream からの SSE ストリームを傍受しながらクライアントに転送する。
// アイドルタイムアウトを超過するとストリームを閉じる。
//
// スキャナ goroutine は body.Read() でブロックする可能性がある。
// アイドルタイムアウトや ctx キャンセルで本関数が return した後も、
// スキャナ goroutine は body.Read() の完了まで残る。
// 呼び出し元の defer resp.Body.Close() により body が閉じられ、
// Read がエラーを返してスキャナ goroutine は終了する。
func (p *HTTPProxy) streamSSE(ctx context.Context, w http.ResponseWriter, body io.ReadCloser) {
	p.drainWg.Add(1)
	defer p.drainWg.Done()

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

	ch := make(chan *SSEEvent, 1)
	go func() {
		defer close(ch)
		scanner := NewSSEScanner(body)
		for scanner.Scan() {
			ev := scanner.Event()
			select {
			case ch <- &SSEEvent{ID: ev.ID, Event: ev.Event, Data: ev.Data}:
			case <-ctx.Done():
				return
			}
		}
	}()

	idleTimer := time.NewTimer(p.sseIdleTimeout)
	defer idleTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-idleTimer.C:
			slog.Warn("SSE idle timeout reached, closing stream")
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}

			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(p.sseIdleTimeout)

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
				slog.Warn("SSE event blocked", "reason", result.Reason)
				continue
			}

			// ActionRedact の場合はリダクション済みデータで SSE イベントを書き換える
			if result.Action == intercept.ActionRedact && result.RedactedBody != nil {
				ev = &SSEEvent{ID: ev.ID, Event: ev.Event, Data: string(result.RedactedBody)}
			}

			formatted := FormatSSEEvent(ev)
			if _, err := w.Write(formatted); err != nil {
				slog.Error("SSE write error", "error", err)
				return
			}
			flusher.Flush()
		}
	}
}

// setProxyHeaders は upstream リクエストにプロキシヘッダを設定する。
func setProxyHeaders(upReq *http.Request, r *http.Request) {
	if r.RemoteAddr != "" {
		// RemoteAddr は "IP:port" 形式 — XFF には IP のみ設定する（RFC 7239）
		clientIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			clientIP = host
		}
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

	resp := p.doUpstream(w, upReq)
	if resp == nil {
		return
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		p.trackSession(sid)
		w.Header().Set("Mcp-Session-Id", sid)
	}

	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		p.streamSSE(r.Context(), w, resp.Body)
		return
	}

	// 非 SSE レスポンス → サイズ制限付きで転送
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxBodySize)); err != nil {
		slog.Error("io.Copy failed in handleGet", "error", err)
	}
}

// handleDelete はセッション終了リクエストを処理する。
func (p *HTTPProxy) handleDelete(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("Mcp-Session-Id")

	delCtx, delCancel := context.WithTimeout(r.Context(), p.requestTimeout)
	defer delCancel()

	upReq, err := http.NewRequestWithContext(delCtx, http.MethodDelete, p.upstream, nil)
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

	resp := p.doUpstream(w, upReq)
	if resp == nil {
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
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxBodySize)); err != nil {
		slog.Error("io.Copy failed in handleDelete", "error", err)
	}
}

// newContextReader は context のキャンセルを io.Reader に伝播する Reader を返す。
// 内部で io.Pipe と 1 つのコピー goroutine を使用する。
// ctx キャンセルは context.AfterFunc で pw を閉じることで伝播する。
// AfterFunc は ctx がキャンセルされるかコピー完了後に stop されるため、
// ctx にデッドラインがない場合でも goroutine リークしない。
//
// 呼び出し元は r（通常 resp.Body）を defer で Close すること。
// ctx キャンセル時、pw.CloseWithError により pr.Read は ctx.Err() を返す。
// 正常完了時はコピー goroutine が pw.CloseWithError(nil) で EOF を伝播する。
func newContextReader(ctx context.Context, r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	stop := context.AfterFunc(ctx, func() {
		pw.CloseWithError(ctx.Err())
	})
	go func() {
		_, err := io.Copy(pw, r)
		stop()
		pw.CloseWithError(err)
	}()
	return pr
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
