package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWKSConfig は JWKS エンドポイントからの鍵取得設定。
type JWKSConfig struct {
	URL      string
	CacheTTL time.Duration // デフォルト 1h
}

// jwkKey は JWKS レスポンス中の個別鍵を表す。
type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA パラメータ
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC パラメータ
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// jwksResponse は JWKS エンドポイントのレスポンスを表す。
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// JWKSKeyProvider は JWKS エンドポイントから公開鍵を取得・キャッシュする。
// スレッドセーフであり、鍵 ID ミス時に自動で再取得を行う。
type JWKSKeyProvider struct {
	url      string
	cacheTTL time.Duration
	client   *http.Client

	mu        sync.RWMutex
	keys      map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	fetchedAt time.Time
}

// NewJWKSKeyProvider は JWKSConfig から JWKSKeyProvider を構築する。
func NewJWKSKeyProvider(cfg JWKSConfig) *JWKSKeyProvider {
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	return &JWKSKeyProvider{
		url:      cfg.URL,
		cacheTTL: ttl,
		client:   &http.Client{Timeout: 10 * time.Second},
		keys:     make(map[string]any),
	}
}

// GetKey は指定された kid に対応する公開鍵を返す。
// キャッシュが有効であればキャッシュから取得し、
// kid がキャッシュに無い場合は自動で再フェッチを試みる。
func (p *JWKSKeyProvider) GetKey(kid string) (any, error) {
	// まずキャッシュを確認
	p.mu.RLock()
	key, ok := p.keys[kid]
	expired := time.Since(p.fetchedAt) > p.cacheTTL
	p.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	// キャッシュミスまたは期限切れ → 再フェッチ
	if err := p.refresh(); err != nil {
		return nil, fmt.Errorf("auth/jwks: failed to refresh keys: %w", err)
	}

	p.mu.RLock()
	key, ok = p.keys[kid]
	p.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("auth/jwks: key ID %q not found", kid)
	}
	return key, nil
}

// KeyFunc は jwt.Keyfunc を返す。
// jwt.Parse に渡して使用する。
func (p *JWKSKeyProvider) KeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("auth/jwks: token header missing kid")
		}
		return p.GetKey(kid)
	}
}

// refresh は JWKS エンドポイントから鍵セットを取得し、キャッシュを更新する。
func (p *JWKSKeyProvider) refresh() error {
	resp, err := p.client.Get(p.url)
	if err != nil {
		return fmt.Errorf("auth/jwks: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth/jwks: unexpected status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("auth/jwks: failed to decode response: %w", err)
	}

	keys := make(map[string]any, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue // 署名用以外の鍵はスキップ
		}
		pubKey, err := parseJWK(k)
		if err != nil {
			// パースできない鍵はスキップし、他の鍵の処理を継続する
			continue
		}
		keys[k.Kid] = pubKey
	}

	p.mu.Lock()
	p.keys = keys
	p.fetchedAt = time.Now()
	p.mu.Unlock()

	return nil
}

// parseJWK は JWK を *rsa.PublicKey または *ecdsa.PublicKey に変換する。
func parseJWK(k jwkKey) (any, error) {
	switch k.Kty {
	case "RSA":
		return parseRSAJWK(k)
	case "EC":
		return parseECJWK(k)
	default:
		return nil, fmt.Errorf("auth/jwks: unsupported key type %q", k.Kty)
	}
}

// parseRSAJWK は RSA JWK を *rsa.PublicKey に変換する。
func parseRSAJWK(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("auth/jwks: invalid RSA n parameter: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("auth/jwks: invalid RSA e parameter: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("auth/jwks: RSA exponent too large")
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// parseECJWK は EC JWK を *ecdsa.PublicKey に変換する。
func parseECJWK(k jwkKey) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("auth/jwks: unsupported curve %q", k.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("auth/jwks: invalid EC x parameter: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("auth/jwks: invalid EC y parameter: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// 鍵が曲線上の有効な点であることを検証する
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("auth/jwks: EC point is not on curve %q", k.Crv)
	}

	return pubKey, nil
}
