package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Middleware は HTTP 認証ミドルウェア。
// JWT と API key の両方をサポートする。
type Middleware struct {
	jwt    *JWTValidator
	apikey *APIKeyValidator
}

// NewMiddleware は認証ミドルウェアを構築する。
// jwt, apikey のいずれも nil の場合、認証なし（全通過）。
func NewMiddleware(jwt *JWTValidator, apikey *APIKeyValidator) *Middleware {
	return &Middleware{jwt: jwt, apikey: apikey}
}

// Wrap は next ハンドラを認証ミドルウェアでラップする。
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 両 validator nil → 認証なし
		if m.jwt == nil && m.apikey == nil {
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
			if m.jwt == nil {
				unauthorized(w)
				return
			}
			id, err := m.jwt.Validate(credential)
			if err != nil {
				unauthorized(w)
				return
			}
			r = r.WithContext(WithIdentity(r.Context(), id))
			next.ServeHTTP(w, r)

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
