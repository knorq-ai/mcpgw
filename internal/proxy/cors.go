package proxy

import "net/http"

// CORSMiddleware は CORS プリフライトおよびレスポンスヘッダを処理する。
type CORSMiddleware struct {
	allowedOrigins map[string]struct{}
	allowAll       bool
}

// NewCORSMiddleware は CORSMiddleware を生成する。
// origins が空の場合は nil を返す（CORS 無効）。
func NewCORSMiddleware(origins []string) *CORSMiddleware {
	if len(origins) == 0 {
		return nil
	}
	m := &CORSMiddleware{
		allowedOrigins: make(map[string]struct{}, len(origins)),
	}
	for _, o := range origins {
		if o == "*" {
			m.allowAll = true
		}
		m.allowedOrigins[o] = struct{}{}
	}
	return m
}

// Wrap は CORS ミドルウェアでハンドラをラップする。
func (c *CORSMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if c.isAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, Mcp-Session-Id, X-Request-Id")
				w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, X-Request-Id")
				w.Header().Set("Access-Control-Max-Age", "86400")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (c *CORSMiddleware) isAllowed(origin string) bool {
	if c.allowAll {
		return true
	}
	_, ok := c.allowedOrigins[origin]
	return ok
}
