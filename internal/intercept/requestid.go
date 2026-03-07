package intercept

import "context"

type requestIDKey struct{}

// WithRequestID はコンテキストにリクエスト ID を設定する。
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext はコンテキストからリクエスト ID を取得する。
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}
