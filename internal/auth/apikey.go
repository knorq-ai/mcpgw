package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// APIKeyEntry は API キーとその名前のペア。
type APIKeyEntry struct {
	Key  string
	Name string
}

// APIKeyValidator は API キーを検証する。
type APIKeyValidator struct {
	keys []APIKeyEntry
}

// NewAPIKeyValidator は APIKeyValidator を構築する。
func NewAPIKeyValidator(keys []APIKeyEntry) *APIKeyValidator {
	return &APIKeyValidator{keys: keys}
}

// Validate は API キーを検証し、Identity を返す。
// HMAC-SHA256 ダイジェストを経由した constant-time 比較でタイミング攻撃を防止する。
// 直接 ConstantTimeCompare すると長さの不一致で即座に 0 を返すため、
// まず固定長ダイジェストに変換してから比較する。
func (v *APIKeyValidator) Validate(key string) (*Identity, error) {
	for _, entry := range v.keys {
		if keyEqual(key, entry.Key) {
			return &Identity{
				Subject: entry.Name,
				Method:  "apikey",
			}, nil
		}
	}
	return nil, fmt.Errorf("auth: invalid API key")
}

// keyEqual は HMAC-SHA256 ダイジェストで固定長にしてから constant-time 比較する。
func keyEqual(a, b string) bool {
	mac := hmac.New(sha256.New, []byte("mcpgw-apikey-compare"))
	mac.Write([]byte(a))
	hashA := mac.Sum(nil)

	mac.Reset()
	mac.Write([]byte(b))
	hashB := mac.Sum(nil)

	return subtle.ConstantTimeCompare(hashA, hashB) == 1
}
