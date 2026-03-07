package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTHS256Valid(t *testing.T) {
	secret := []byte("test-secret-key-32bytes-long!!")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(secret)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})
	require.NoError(t, err)

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user-1", id.Subject)
	assert.Equal(t, "jwt", id.Method)
	assert.Equal(t, "user-1", id.Claims["sub"])
}

func TestJWTHS256Expired(t *testing.T) {
	secret := []byte("test-secret-key-32bytes-long!!")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(secret)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})
	require.NoError(t, err)

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestJWTHS256WrongSecret(t *testing.T) {
	secret := []byte("correct-secret")
	wrongSecret := []byte("wrong-secret")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(wrongSecret)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})
	require.NoError(t, err)

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
}

func TestJWTRS256Valid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "service-account",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(privateKey)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "RS256", PublicKey: &privateKey.PublicKey})
	require.NoError(t, err)

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "service-account", id.Subject)
	assert.Equal(t, "jwt", id.Method)
}

func TestJWTRS256WrongKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(privateKey)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "RS256", PublicKey: &wrongKey.PublicKey})
	require.NoError(t, err)

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
}

func TestJWTES256Valid(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "ecdsa-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(privateKey)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "ES256", PublicKey: &privateKey.PublicKey})
	require.NoError(t, err)

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "ecdsa-user", id.Subject)
}

func TestJWTES256WrongKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(privateKey)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "ES256", PublicKey: &wrongKey.PublicKey})
	require.NoError(t, err)

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
}

func TestJWTAlgorithmConfusion(t *testing.T) {
	// HS256 バリデータに RS256 トークンを渡す → 拒否される
	secret := []byte("shared-secret")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(privateKey)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})
	require.NoError(t, err)

	_, err = v.Validate(tokenStr)
	require.Error(t, err)
}

func TestJWTSubClaimExtraction(t *testing.T) {
	secret := []byte("test-secret")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "user-42",
		"email": "user@example.com",
		"roles": []string{"admin"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(secret)
	require.NoError(t, err)

	v, err := NewJWTValidator(JWTConfig{Algorithm: "HS256", Secret: secret})
	require.NoError(t, err)

	id, err := v.Validate(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "user-42", id.Subject)
	assert.Equal(t, "user@example.com", id.Claims["email"])
}

func TestJWTConfigValidation(t *testing.T) {
	_, err := NewJWTValidator(JWTConfig{Algorithm: "HS256"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret")

	_, err = NewJWTValidator(JWTConfig{Algorithm: "RS256"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key")

	_, err = NewJWTValidator(JWTConfig{Algorithm: "ES256"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key")

	_, err = NewJWTValidator(JWTConfig{Algorithm: "none"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}
