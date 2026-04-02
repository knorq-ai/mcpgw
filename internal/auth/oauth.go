package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// OAuthConfig は OAuth 2.1 トークン検証の設定。
type OAuthConfig struct {
	JWKSURL     string // JWKS エンドポイント URL
	Issuer      string // 期待される iss クレーム
	Audience    string // 期待される aud クレーム
	ResourceURL string // RFC 8707 リソースインジケータ
}

// OAuthValidator は JWKS を用いて OAuth 2.1 トークンを検証する。
type OAuthValidator struct {
	jwks     *JWKSKeyProvider
	issuer   string
	audience string
	resource string
}

// NewOAuthValidator は OAuthConfig から OAuthValidator を構築する。
func NewOAuthValidator(cfg OAuthConfig) (*OAuthValidator, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("auth/oauth: JWKS URL is required")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("auth/oauth: issuer is required")
	}

	jwks := NewJWKSKeyProvider(JWKSConfig{URL: cfg.JWKSURL})

	return &OAuthValidator{
		jwks:     jwks,
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		resource: cfg.ResourceURL,
	}, nil
}

// Validate は OAuth 2.1 トークン文字列を検証し、Identity を返す。
// issuer, audience, resource の各クレームを検証する。
func (v *OAuthValidator) Validate(tokenStr string) (*Identity, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithIssuer(v.issuer),
	}
	if v.audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.audience))
	}

	token, err := jwt.Parse(tokenStr, v.jwks.KeyFunc(), parserOpts...)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("auth/oauth: unexpected claims type")
	}

	// RFC 8707 リソースインジケータの検証
	if v.resource != "" {
		if err := validateResource(claims, v.resource); err != nil {
			return nil, err
		}
	}

	sub, _ := claims.GetSubject()

	// claims を map[string]any にコピー
	claimsMap := make(map[string]any, len(claims))
	for k, val := range claims {
		claimsMap[k] = val
	}

	// ロールの抽出
	roles := extractRoles(claimsMap, "roles")

	return &Identity{
		Subject: sub,
		Method:  "jwt",
		Claims:  claimsMap,
		Roles:   roles,
	}, nil
}

// validateResource は RFC 8707 のリソースインジケータを検証する。
// トークンの aud クレームに resource が含まれているか確認する。
func validateResource(claims jwt.MapClaims, resource string) error {
	aud, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("auth/oauth: failed to get audience: %w", err)
	}

	for _, a := range aud {
		if a == resource {
			return nil
		}
	}

	return fmt.Errorf("auth/oauth: token audience does not contain resource %q", resource)
}

// oauthMetadata は OAuth 2.1 認可サーバメタデータ（RFC 8414 / RFC 9728）を表す。
type oauthMetadata struct {
	Issuer                            string   `json:"issuer"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResourceRegistration              string   `json:"resource_registration_endpoint,omitempty"`
}

// WellKnownHandler は /.well-known/oauth-authorization-server メタデータを返すハンドラを生成する。
// RFC 8414 および RFC 9728 に準拠したメタデータを提供する。
func WellKnownHandler(issuer, jwksURL string) http.HandlerFunc {
	meta := oauthMetadata{
		Issuer:                            issuer,
		JWKSURI:                           jwksURL,
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "private_key_jwt"},
		ScopesSupported:                   []string{"mcp:tools", "mcp:resources", "mcp:prompts"},
	}

	body, _ := json.Marshal(meta)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(body)
	}
}
