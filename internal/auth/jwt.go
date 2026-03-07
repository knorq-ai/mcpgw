package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig は JWT 検証の設定。
type JWTConfig struct {
	Algorithm string // "HS256", "RS256", "ES256"
	Secret    []byte // HS256 用共有シークレット
	PublicKey any    // *rsa.PublicKey or *ecdsa.PublicKey（RS256/ES256 用）
}

// JWTValidator は JWT トークンを検証する。
type JWTValidator struct {
	algorithm string
	keyFunc   jwt.Keyfunc
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

	return &JWTValidator{
		algorithm: cfg.Algorithm,
		keyFunc:   keyFunc,
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
	for k, v := range claims {
		claimsMap[k] = v
	}

	return &Identity{
		Subject: sub,
		Method:  "jwt",
		Claims:  claimsMap,
	}, nil
}
