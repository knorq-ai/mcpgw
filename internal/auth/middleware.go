package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Middleware は HTTP 認証ミドルウェア。
// JWT, API key, OAuth 2.1 をサポートする。
type Middleware struct {
	jwt    *JWTValidator
	apikey *APIKeyValidator
	oauth  *OAuthValidator
}

// NewMiddleware は認証ミドルウェアを構築する。
// 全 validator が nil の場合、認証なし（全通過）。
func NewMiddleware(jwt *JWTValidator, apikey *APIKeyValidator, opts ...MiddlewareOption) *Middleware {
	m := &Middleware{jwt: jwt, apikey: apikey}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// MiddlewareOption は Middleware の追加設定。
type MiddlewareOption func(*Middleware)

// WithOAuth は OAuth 2.1 バリデータを設定する。
func WithOAuth(v *OAuthValidator) MiddlewareOption {
	return func(m *Middleware) { m.oauth = v }
}

// Wrap は next ハンドラを認証ミドルウェアでラップする。
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 全 validator nil → 認証なし
		if m.jwt == nil && m.apikey == nil && m.oauth == nil {
			next.ServeHTTP(w, r)
			return
		}

		// X-API-Key ヘッダ → API key 検証
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" && m.apikey != nil {
			id, err := m.apikey.Validate(apiKey)
			if err != nil {
				unauthorized(w)
				return
			}
			r = r.WithContext(WithIdentity(r.Context(), id))
			next.ServeHTTP(w, r)
			return
		}

		// Authorization ヘッダ
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			unauthorized(w)
			return
		}

		scheme, credential, ok := parseAuthHeader(authHeader)
		if !ok {
			unauthorized(w)
			return
		}

		switch scheme {
		case "bearer":
			// JWT → OAuth の順にフォールバック
			if id, err := m.validateBearer(credential); err == nil {
				r = r.WithContext(WithIdentity(r.Context(), id))
				next.ServeHTTP(w, r)
				return
			}
			unauthorized(w)

		case "apikey":
			if m.apikey == nil {
				unauthorized(w)
				return
			}
			id, err := m.apikey.Validate(credential)
			if err != nil {
				unauthorized(w)
				return
			}
			r = r.WithContext(WithIdentity(r.Context(), id))
			next.ServeHTTP(w, r)

		default:
			unauthorized(w)
		}
	})
}

// validateBearer は Bearer トークンを JWT → OAuth の順で検証する。
func (m *Middleware) validateBearer(token string) (*Identity, error) {
	if m.jwt != nil {
		if id, err := m.jwt.Validate(token); err == nil {
			return id, nil
		}
	}
	if m.oauth != nil {
		if id, err := m.oauth.Validate(token); err == nil {
			return id, nil
		}
	}
	return nil, fmt.Errorf("bearer token validation failed")
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
}

// parseAuthHeader は "Scheme credential" 形式のヘッダを分割する。
func parseAuthHeader(header string) (scheme, credential string, ok bool) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", false
	}
	return strings.ToLower(parts[0]), parts[1], true
}
