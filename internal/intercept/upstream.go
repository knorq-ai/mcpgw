package intercept

import "context"

type upstreamKey struct{}

// WithUpstream はコンテキストに upstream URL を設定する。
func WithUpstream(ctx context.Context, upstream string) context.Context {
	return context.WithValue(ctx, upstreamKey{}, upstream)
}

// UpstreamFromContext はコンテキストから upstream URL を取得する。
func UpstreamFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(upstreamKey{}).(string); ok {
		return v
	}
	return ""
}
