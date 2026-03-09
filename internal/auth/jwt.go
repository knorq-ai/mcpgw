package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig は JWT 検証の設定。
type JWTConfig struct {
	Algorithm  string // "HS256", "RS256", "ES256"
	Secret     []byte // HS256 用共有シークレット
	PublicKey  any    // *rsa.PublicKey or *ecdsa.PublicKey（RS256/ES256 用）
	RolesClaim string // ロール抽出元の claim 名（空の場合は "roles"）
}

// JWTValidator は JWT トークンを検証する。
type JWTValidator struct {
	algorithm  string
	keyFunc    jwt.Keyfunc
	rolesClaim string // ロール抽出元の claim 名（デフォルト: "roles"）
}

// NewJWTValidator は JWTConfig から JWTValidator を構築する。
func NewJWTValidator(cfg JWTConfig) (*JWTValidator, error) {
	var keyFunc jwt.Keyfunc

	switch cfg.Algorithm {
	case "HS256":
		if len(cfg.Secret) == 0 {
			return nil, fmt.Errorf("auth: HS256 requires a secret")
		}
		keyFunc = func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != "HS256" {
				return nil, fmt.Errorf("auth: unexpected signing method: %s", t.Method.Alg())
			}
			return cfg.Secret, nil
		}
	case "RS256":
		if cfg.PublicKey == nil {
			return nil, fmt.Errorf("auth: RS256 requires a public key")
		}
		keyFunc = func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != "RS256" {
				return nil, fmt.Errorf("auth: unexpected signing method: %s", t.Method.Alg())
			}
			return cfg.PublicKey, nil
		}
	case "ES256":
		if cfg.PublicKey == nil {
			return nil, fmt.Errorf("auth: ES256 requires a public key")
		}
		keyFunc = func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != "ES256" {
				return nil, fmt.Errorf("auth: unexpected signing method: %s", t.Method.Alg())
			}
			return cfg.PublicKey, nil
		}
	default:
		return nil, fmt.Errorf("auth: unsupported algorithm %q", cfg.Algorithm)
	}

	rolesClaim := cfg.RolesClaim
	if rolesClaim == "" {
		rolesClaim = "roles"
	}

	return &JWTValidator{
		algorithm:  cfg.Algorithm,
		keyFunc:    keyFunc,
		rolesClaim: rolesClaim,
	}, nil
}

// Validate は JWT トークン文字列を検証し、Identity を返す。
func (v *JWTValidator) Validate(tokenStr string) (*Identity, error) {
	token, err := jwt.Parse(tokenStr, v.keyFunc,
		jwt.WithValidMethods([]string{v.algorithm}),
	)
	if err != nil {
		return nil, fmt.Errorf("auth: invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("auth: unexpected claims type")
	}

	sub, _ := claims.GetSubject()

	// claims を map[string]any にコピー
	claimsMap := make(map[string]any, len(claims))
	for k, val := range claims {
		claimsMap[k] = val
	}

	// ロールの抽出
	roles := extractRoles(claimsMap, v.rolesClaim)

	return &Identity{
		Subject: sub,
		Method:  "jwt",
		Claims:  claimsMap,
		Roles:   roles,
	}, nil
}

// extractRoles は JWT claims からロールを抽出する。
// claim 値が文字列スライスの場合はそのまま、単一文字列の場合は1要素スライスにする。
func extractRoles(claims map[string]any, claimName string) []string {
	val, ok := claims[claimName]
	if !ok {
		return nil
	}

	switch v := val.(type) {
	case []any:
		roles := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				roles = append(roles, s)
			}
		}
		return roles
	case []string:
		return v
	case string:
		return []string{v}
	default:
		return nil
	}
}
