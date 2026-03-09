package telemetry

import "context"

// コンテキストキー型（エクスポートしない）
type traceIDKey struct{}
type spanIDKey struct{}

// withTraceContext はコンテキストに trace ID と span ID を設定する。
func withTraceContext(ctx context.Context, traceID, spanID string) context.Context {
	ctx = context.WithValue(ctx, traceIDKey{}, traceID)
	ctx = context.WithValue(ctx, spanIDKey{}, spanID)
	return ctx
}

// traceIDFromContext はコンテキストから trace ID を取得する（パッケージ内部用）。
func traceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(traceIDKey{}).(string); ok {
		return v
	}
	return ""
}

// TraceIDFromContext はコンテキストから trace ID を取得する。
// トレースが開始されていない場合は空文字列を返す。
func TraceIDFromContext(ctx context.Context) string {
	return traceIDFromContext(ctx)
}

// SpanIDFromContext はコンテキストから span ID を取得する。
// スパンが開始されていない場合は空文字列を返す。
func SpanIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(spanIDKey{}).(string); ok {
		return v
	}
	return ""
}
