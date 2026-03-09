package auth

import "context"

// Identity は認証されたクライアントの情報を表す。
type Identity struct {
	Subject string         `json:"sub"`
	Method  string         `json:"method"` // "jwt" or "apikey"
	Claims  map[string]any `json:"claims,omitempty"`
	Roles   []string       `json:"roles,omitempty"` // JWT claims から抽出されたロール
}

type contextKey struct{}

// WithIdentity は Identity をコンテキストに格納する。
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// FromContext はコンテキストから Identity を取り出す。
// 認証されていない場合は nil を返す。
func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(contextKey{}).(*Identity)
	return id
}
