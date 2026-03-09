package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupOAuthTestServer はテスト用の JWKS サーバと RSA 秘密鍵を返す。
func setupOAuthTestServer(t *testing.T, kid string) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	body := rsaJWKS(kid, &privateKey.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	return srv, privateKey
}

// signToken は指定された claims と秘密鍵で JWT トークンを生成する。
func signToken(t *testing.T, kid string, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenStr, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return tokenStr
}

func TestOAuthValidatorValid(t *testing.T) {
	kid := "oauth-key-1"
	srv, privateKey := setupOAuthTestServer(t, kid)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL:  srv.URL,
		Issuer:   "https://auth.example.com",
		Audience: "https://api.example.com",
	})
	require.NoError(t, err)

	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub":   "user-oauth-1",
		"iss":   "https://auth.example.com",
		"aud":   "https://api.example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"roles": []string{"reader", "writer"},
	})

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user-oauth-1", id.Subject)
	assert.Equal(t, "jwt", id.Method)
	assert.Equal(t, []string{"reader", "writer"}, id.Roles)
}

func TestOAuthValidatorExpired(t *testing.T) {
	kid := "oauth-key-2"
	srv, privateKey := setupOAuthTestServer(t, kid)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL: srv.URL,
		Issuer:  "https://auth.example.com",
	})
	require.NoError(t, err)

	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub": "user-expired",
		"iss": "https://auth.example.com",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestOAuthValidatorWrongIssuer(t *testing.T) {
	kid := "oauth-key-3"
	srv, privateKey := setupOAuthTestServer(t, kid)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL: srv.URL,
		Issuer:  "https://auth.example.com",
	})
	require.NoError(t, err)

	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub": "user-wrong-iss",
		"iss": "https://evil.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestOAuthValidatorWrongAudience(t *testing.T) {
	kid := "oauth-key-4"
	srv, privateKey := setupOAuthTestServer(t, kid)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL:  srv.URL,
		Issuer:   "https://auth.example.com",
		Audience: "https://api.example.com",
	})
	require.NoError(t, err)

	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub": "user-wrong-aud",
		"iss": "https://auth.example.com",
		"aud": "https://wrong-api.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestOAuthValidatorResourceIndicator(t *testing.T) {
	kid := "oauth-key-5"
	srv, privateKey := setupOAuthTestServer(t, kid)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL:     srv.URL,
		Issuer:      "https://auth.example.com",
		Audience:    "https://resource.example.com",
		ResourceURL: "https://resource.example.com",
	})
	require.NoError(t, err)

	// aud に resource が含まれるトークン → 成功
	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub": "user-resource",
		"iss": "https://auth.example.com",
		"aud": "https://resource.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user-resource", id.Subject)
}

func TestOAuthValidatorResourceIndicatorMismatch(t *testing.T) {
	kid := "oauth-key-6"
	srv, privateKey := setupOAuthTestServer(t, kid)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL:     srv.URL,
		Issuer:      "https://auth.example.com",
		ResourceURL: "https://resource.example.com",
	})
	require.NoError(t, err)

	// aud に resource が含まれないトークン → 失敗
	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub": "user-resource-bad",
		"iss": "https://auth.example.com",
		"aud": "https://other-resource.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resource")
}

func TestOAuthValidatorResourceIndicatorMultipleAudiences(t *testing.T) {
	kid := "oauth-key-7"
	srv, privateKey := setupOAuthTestServer(t, kid)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL:     srv.URL,
		Issuer:      "https://auth.example.com",
		ResourceURL: "https://resource-b.example.com",
	})
	require.NoError(t, err)

	// 複数 aud のうち一つが resource に一致する場合 → 成功
	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub": "user-multi-aud",
		"iss": "https://auth.example.com",
		"aud": jwt.ClaimStrings{"https://resource-a.example.com", "https://resource-b.example.com"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user-multi-aud", id.Subject)
}

func TestOAuthValidatorNoAudienceRequired(t *testing.T) {
	kid := "oauth-key-8"
	srv, privateKey := setupOAuthTestServer(t, kid)

	// Audience を指定しない → aud 検証をスキップ
	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL: srv.URL,
		Issuer:  "https://auth.example.com",
	})
	require.NoError(t, err)

	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub": "user-no-aud",
		"iss": "https://auth.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user-no-aud", id.Subject)
}

func TestNewOAuthValidatorMissingJWKSURL(t *testing.T) {
	_, err := NewOAuthValidator(OAuthConfig{
		Issuer: "https://auth.example.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS URL")
}

func TestNewOAuthValidatorMissingIssuer(t *testing.T) {
	_, err := NewOAuthValidator(OAuthConfig{
		JWKSURL: "https://auth.example.com/.well-known/jwks.json",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestWellKnownHandler(t *testing.T) {
	handler := WellKnownHandler(
		"https://auth.example.com",
		"https://auth.example.com/.well-known/jwks.json",
	)

	t.Run("GET returns metadata", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age=3600")

		var meta map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &meta)
		require.NoError(t, err)

		assert.Equal(t, "https://auth.example.com", meta["issuer"])
		assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", meta["jwks_uri"])

		// response_types_supported が存在することを確認
		respTypes, ok := meta["response_types_supported"].([]any)
		require.True(t, ok)
		assert.Contains(t, respTypes, "code")
	})

	t.Run("POST returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-authorization-server", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, http.MethodGet, rec.Header().Get("Allow"))
	})
}

func TestWellKnownHandlerMetadataFields(t *testing.T) {
	handler := WellKnownHandler(
		"https://auth.example.com",
		"https://auth.example.com/jwks",
	)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var meta map[string]any
	err := json.Unmarshal(rec.Body.Bytes(), &meta)
	require.NoError(t, err)

	// RFC 8414 / RFC 9728 で必須・推奨のフィールドが含まれることを確認
	assert.Contains(t, meta, "issuer")
	assert.Contains(t, meta, "jwks_uri")
	assert.Contains(t, meta, "response_types_supported")
	assert.Contains(t, meta, "subject_types_supported")
	assert.Contains(t, meta, "token_endpoint_auth_methods_supported")
	assert.Contains(t, meta, "scopes_supported")

	// MCP 固有のスコープが含まれることを確認
	scopes, ok := meta["scopes_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, scopes, "mcp:tools")
	assert.Contains(t, scopes, "mcp:resources")
	assert.Contains(t, scopes, "mcp:prompts")
}

func TestOAuthValidatorClaimsExtraction(t *testing.T) {
	kid := "oauth-key-claims"
	srv, privateKey := setupOAuthTestServer(t, kid)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL: srv.URL,
		Issuer:  "https://auth.example.com",
	})
	require.NoError(t, err)

	tokenStr := signToken(t, kid, privateKey, jwt.MapClaims{
		"sub":   "user-claims",
		"iss":   "https://auth.example.com",
		"email": "user@example.com",
		"scope": "mcp:tools mcp:resources",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user-claims", id.Subject)
	assert.Equal(t, "user@example.com", id.Claims["email"])
	assert.Equal(t, "mcp:tools mcp:resources", id.Claims["scope"])
}

func TestOAuthValidatorInvalidSignature(t *testing.T) {
	kid := "oauth-key-sig"
	srv, _ := setupOAuthTestServer(t, kid)

	// 別の鍵で署名する
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	v, err := NewOAuthValidator(OAuthConfig{
		JWKSURL: srv.URL,
		Issuer:  "https://auth.example.com",
	})
	require.NoError(t, err)

	tokenStr := signToken(t, kid, otherKey, jwt.MapClaims{
		"sub": "user-bad-sig",
		"iss": "https://auth.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}
