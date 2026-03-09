package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaJWKS はテスト用に RSA 公開鍵から JWKS JSON を生成する。
func rsaJWKS(kid string, pub *rsa.PublicKey) []byte {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	resp := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// ecJWKS はテスト用に EC 公開鍵から JWKS JSON を生成する。
func ecJWKS(kid string, pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	// 固定長にパディングする
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	x := base64.RawURLEncoding.EncodeToString(xPadded)
	y := base64.RawURLEncoding.EncodeToString(yPadded)

	resp := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"kid": kid,
				"use": "sig",
				"alg": "ES256",
				"crv": "P-256",
				"x":   x,
				"y":   y,
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestJWKSKeyProviderRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	body := rsaJWKS("rsa-key-1", &privateKey.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{URL: srv.URL})

	key, err := provider.GetKey("rsa-key-1")
	require.NoError(t, err)

	rsaKey, ok := key.(*rsa.PublicKey)
	require.True(t, ok, "取得した鍵は *rsa.PublicKey であるべき")
	assert.Equal(t, privateKey.PublicKey.N.Cmp(rsaKey.N), 0)
	assert.Equal(t, privateKey.PublicKey.E, rsaKey.E)
}

func TestJWKSKeyProviderEC(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	body := ecJWKS("ec-key-1", &privateKey.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{URL: srv.URL})

	key, err := provider.GetKey("ec-key-1")
	require.NoError(t, err)

	ecKey, ok := key.(*ecdsa.PublicKey)
	require.True(t, ok, "取得した鍵は *ecdsa.PublicKey であるべき")
	assert.Equal(t, privateKey.PublicKey.X.Cmp(ecKey.X), 0)
	assert.Equal(t, privateKey.PublicKey.Y.Cmp(ecKey.Y), 0)
}

func TestJWKSKeyProviderKeyNotFound(t *testing.T) {
	body := []byte(`{"keys": []}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{URL: srv.URL})

	_, err := provider.GetKey("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestJWKSKeyProviderCacheTTL(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fetchCount := 0
	body := rsaJWKS("key-1", &privateKey.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{
		URL:      srv.URL,
		CacheTTL: time.Hour, // 長い TTL
	})

	// 初回フェッチ
	_, err = provider.GetKey("key-1")
	require.NoError(t, err)
	assert.Equal(t, 1, fetchCount)

	// 2回目はキャッシュから取得（フェッチ回数増加なし）
	_, err = provider.GetKey("key-1")
	require.NoError(t, err)
	assert.Equal(t, 1, fetchCount)
}

func TestJWKSKeyProviderAutoRotation(t *testing.T) {
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// 初回は key-1 のみ返し、2回目以降は key-1 と key-2 を返す
	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		if fetchCount == 1 {
			w.Write(rsaJWKS("key-1", &privateKey1.PublicKey))
		} else {
			// 両方の鍵を含むレスポンス
			resp := map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"kid": "key-1",
						"use": "sig",
						"alg": "RS256",
						"n":   base64.RawURLEncoding.EncodeToString(privateKey1.PublicKey.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey1.PublicKey.E)).Bytes()),
					},
					{
						"kty": "RSA",
						"kid": "key-2",
						"use": "sig",
						"alg": "RS256",
						"n":   base64.RawURLEncoding.EncodeToString(privateKey2.PublicKey.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey2.PublicKey.E)).Bytes()),
					},
				},
			}
			b, _ := json.Marshal(resp)
			w.Write(b)
		}
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{
		URL:      srv.URL,
		CacheTTL: time.Hour,
	})

	// key-1 を取得（初回フェッチ）
	_, err = provider.GetKey("key-1")
	require.NoError(t, err)
	assert.Equal(t, 1, fetchCount)

	// key-2 はキャッシュに無い → 自動再フェッチで取得
	key2, err := provider.GetKey("key-2")
	require.NoError(t, err)
	assert.Equal(t, 2, fetchCount)

	rsaKey2, ok := key2.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, privateKey2.PublicKey.N.Cmp(rsaKey2.N), 0)
}

func TestJWKSKeyProviderHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{URL: srv.URL})

	_, err := provider.GetKey("any-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status")
}

func TestJWKSKeyProviderInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("invalid json"))
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{URL: srv.URL})

	_, err := provider.GetKey("any-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestJWKSKeyFuncWithJWTParse(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	body := rsaJWKS("test-kid", &privateKey.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{URL: srv.URL})

	// kid 付きの JWT トークンを生成
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "jwks-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "test-kid"
	tokenStr, err := token.SignedString(privateKey)
	require.NoError(t, err)

	// KeyFunc を使って jwt.Parse で検証
	parsed, err := jwt.Parse(tokenStr, provider.KeyFunc())
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "jwks-user", sub)
}

func TestJWKSKeyFuncMissingKid(t *testing.T) {
	provider := NewJWKSKeyProvider(JWKSConfig{URL: "http://localhost:0"})

	// kid なしのトークン
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte("secret"))
	require.NoError(t, err)

	_, err = jwt.Parse(tokenStr, provider.KeyFunc())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid")
}

func TestJWKSDefaultCacheTTL(t *testing.T) {
	provider := NewJWKSKeyProvider(JWKSConfig{URL: "http://localhost:0"})
	assert.Equal(t, time.Hour, provider.cacheTTL)
}

func TestJWKSCustomCacheTTL(t *testing.T) {
	provider := NewJWKSKeyProvider(JWKSConfig{
		URL:      "http://localhost:0",
		CacheTTL: 30 * time.Minute,
	})
	assert.Equal(t, 30*time.Minute, provider.cacheTTL)
}

func TestJWKSSkipsNonSigKeys(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// use: "enc" の鍵はスキップされるべき
	resp := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "enc-key",
				"use": "enc",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			},
			{
				"kty": "RSA",
				"kid": "sig-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
			},
		},
	}
	body, _ := json.Marshal(resp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{URL: srv.URL})

	// enc 鍵は取得できない
	_, err = provider.GetKey("enc-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// sig 鍵は取得できる
	_, err = provider.GetKey("sig-key")
	require.NoError(t, err)
}

func TestJWKSCacheExpiry(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	fetchCount := 0
	body := rsaJWKS("key-1", &privateKey.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	provider := NewJWKSKeyProvider(JWKSConfig{
		URL:      srv.URL,
		CacheTTL: 1 * time.Millisecond, // 極短 TTL
	})

	// 初回フェッチ
	_, err = provider.GetKey("key-1")
	require.NoError(t, err)
	assert.Equal(t, 1, fetchCount)

	// TTL を超えるまで待つ
	time.Sleep(5 * time.Millisecond)

	// キャッシュ期限切れ → 再フェッチ
	_, err = provider.GetKey("key-1")
	require.NoError(t, err)
	assert.Equal(t, 2, fetchCount)
}
