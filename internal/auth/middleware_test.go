package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dummyHandler は認証成功時に呼ばれるハンドラ。コンテキストから Identity を取得する。
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := FromContext(r.Context())
		if id != nil {
			w.Header().Set("X-Subject", id.Subject)
			w.Header().Set("X-Auth-Method", id.Method)
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddlewareNoAuth(t *testing.T) {
	// 両 validator nil → 認証なし（全通過）
	m := NewMiddleware(nil, nil)
	handler := m.Wrap(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewareJWTBearerValid(t *testing.T) {
	secret := []byte("test-secret")
	jwtV, err := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-jwt",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(secret)
	require.NoError(t, err)

	m := NewMiddleware(jwtV, nil)
	handler := m.Wrap(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user-jwt", rec.Header().Get("X-Subject"))
	assert.Equal(t, "jwt", rec.Header().Get("X-Auth-Method"))
}

func TestMiddlewareJWTBearerInvalid(t *testing.T) {
	secret := []byte("test-secret")
	jwtV, err := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})
	require.NoError(t, err)

	m := NewMiddleware(jwtV, nil)
	handler := m.Wrap(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareAPIKeyHeader(t *testing.T) {
	apikeyV := NewAPIKeyValidator([]APIKeyEntry{
		{Key: "valid-key-123", Name: "service-a"},
	})

	m := NewMiddleware(nil, apikeyV)
	handler := m.Wrap(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "valid-key-123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "service-a", rec.Header().Get("X-Subject"))
	assert.Equal(t, "apikey", rec.Header().Get("X-Auth-Method"))
}

func TestMiddlewareAPIKeyHeaderInvalid(t *testing.T) {
	apikeyV := NewAPIKeyValidator([]APIKeyEntry{
		{Key: "valid-key", Name: "service"},
	})

	m := NewMiddleware(nil, apikeyV)
	handler := m.Wrap(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareAPIKeyAuthorizationHeader(t *testing.T) {
	apikeyV := NewAPIKeyValidator([]APIKeyEntry{
		{Key: "key-from-auth-header", Name: "service-b"},
	})

	m := NewMiddleware(nil, apikeyV)
	handler := m.Wrap(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "ApiKey key-from-auth-header")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "service-b", rec.Header().Get("X-Subject"))
}

func TestMiddlewareNoCredentials(t *testing.T) {
	secret := []byte("test-secret")
	jwtV, _ := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})

	m := NewMiddleware(jwtV, nil)
	handler := m.Wrap(dummyHandler())

	// Authorization ヘッダなし → 401
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareUnsupportedScheme(t *testing.T) {
	secret := []byte("test-secret")
	jwtV, _ := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})

	m := NewMiddleware(jwtV, nil)
	handler := m.Wrap(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareMalformedAuthHeader(t *testing.T) {
	secret := []byte("test-secret")
	jwtV, _ := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})

	m := NewMiddleware(jwtV, nil)
	handler := m.Wrap(dummyHandler())

	// スペースなし
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "BearerNoSpace")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// "Bearer " (credential 空)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMiddlewareBothValidators(t *testing.T) {
	secret := []byte("test-secret")
	jwtV, _ := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})
	apikeyV := NewAPIKeyValidator([]APIKeyEntry{
		{Key: "api-key-1", Name: "api-client"},
	})

	m := NewMiddleware(jwtV, apikeyV)
	handler := m.Wrap(dummyHandler())

	// JWT で認証
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "jwt-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, _ := token.SignedString(secret)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "jwt", rec.Header().Get("X-Auth-Method"))

	// API key で認証
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "api-key-1")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "apikey", rec.Header().Get("X-Auth-Method"))
}

func TestParseAuthHeader(t *testing.T) {
	tests := []struct {
		header     string
		scheme     string
		credential string
		ok         bool
	}{
		{"Bearer token123", "bearer", "token123", true},
		{"ApiKey key123", "apikey", "key123", true},
		{"bearer TOKEN", "bearer", "TOKEN", true},
		{"NoSpace", "", "", false},
		{"Bearer ", "", "", false},
		{"", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			scheme, credential, ok := parseAuthHeader(tt.header)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.scheme, scheme)
				assert.Equal(t, tt.credential, credential)
			}
		})
	}
}
