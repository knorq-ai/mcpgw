// Package telemetry は分散トレーシングの軽量抽象レイヤーを提供する。
// 外部依存なしの no-op 実装をデフォルトとし、将来的に OTel SDK を
// プラグインできる設計である。
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// Config はトレーサー初期化の設定。
type Config struct {
	OTLPEndpoint string  // OTLP エクスポーター宛先（空の場合は no-op）
	ServiceName  string  // サービス名（デフォルト: "mcpgw"）
	SampleRate   float64 // サンプリング率 0.0–1.0（デフォルト: 1.0）
}

// Span はトレーシングスパンの抽象インターフェース。
type Span interface {
	// SetAttribute はスパンに属性を設定する。
	SetAttribute(key string, value string)
	// End はスパンを終了する。
	End()
	// SpanID はスパンの ID を返す。
	SpanID() string
}

// Tracer はスパンの生成とコンテキスト伝播を行うインターフェース。
type Tracer interface {
	// Start は新しいスパンを開始し、スパン情報を含むコンテキストを返す。
	Start(ctx context.Context, name string) (context.Context, Span)
}

// ShutdownFunc はトレーサーリソースのシャットダウン関数。
type ShutdownFunc func(context.Context) error

// globalTracer はプロセス全体のトレーサーインスタンス。
var (
	globalMu     sync.RWMutex
	globalTracer Tracer = &noopTracer{}
)

// SetGlobalTracer はグローバルトレーサーを差し替える。
// OTel SDK 初期化後に呼び出されることを想定している。
func SetGlobalTracer(t Tracer) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalTracer = t
}

// GlobalTracer は現在のグローバルトレーサーを返す。
func GlobalTracer() Tracer {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalTracer
}

// InitTracer はトレーサーを初期化する。
// OTLPEndpoint が空の場合は no-op トレーサーを使用し、ShutdownFunc は何もしない。
// 将来的に OTel SDK を導入する際は、この関数内で SDK 初期化を行い
// SetGlobalTracer でグローバルに設定する。
func InitTracer(cfg Config) (shutdown ShutdownFunc, err error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "mcpgw"
	}
	if cfg.SampleRate <= 0 {
		cfg.SampleRate = 1.0
	}

	if cfg.OTLPEndpoint == "" {
		// no-op: 外部依存なしで動作する
		SetGlobalTracer(&noopTracer{})
		return func(context.Context) error { return nil }, nil
	}

	// TODO: OTel SDK 導入時にここで TracerProvider を構築し、
	// SetGlobalTracer でラップされた Tracer を設定する。
	// 現時点では endpoint が指定されても no-op で動作する。
	SetGlobalTracer(&noopTracer{})
	return func(context.Context) error { return nil }, nil
}

// --- no-op 実装 ---

// noopTracer は何も出力しないデフォルトトレーサー。
type noopTracer struct{}

func (t *noopTracer) Start(ctx context.Context, name string) (context.Context, Span) {
	traceID := traceIDFromContext(ctx)
	if traceID == "" {
		traceID = generateID(16)
	}
	spanID := generateID(8)
	span := &noopSpan{spanID: spanID}
	ctx = withTraceContext(ctx, traceID, spanID)
	return ctx, span
}

// noopSpan は何も出力しないデフォルトスパン。
type noopSpan struct {
	spanID string
}

func (s *noopSpan) SetAttribute(key string, value string) {}
func (s *noopSpan) End()                                  {}
func (s *noopSpan) SpanID() string                        { return s.spanID }

// generateID は指定バイト数のランダム hex ID を生成する。
// trace ID = 16 バイト (32 hex 文字)、span ID = 8 バイト (16 hex 文字)。
func generateID(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// rand.Read の失敗は極めて稀であり、ゼロ埋め ID を返す
		return hex.EncodeToString(make([]byte, nBytes))
	}
	return hex.EncodeToString(b)
}
