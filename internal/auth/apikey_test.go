package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyValid(t *testing.T) {
	v := NewAPIKeyValidator([]APIKeyEntry{
		{Key: "key-abc-123", Name: "service-a"},
		{Key: "key-def-456", Name: "service-b"},
	})

	id, err := v.Validate("key-abc-123")
	require.NoError(t, err)
	assert.Equal(t, "service-a", id.Subject)
	assert.Equal(t, "apikey", id.Method)

	id, err = v.Validate("key-def-456")
	require.NoError(t, err)
	assert.Equal(t, "service-b", id.Subject)
}

func TestAPIKeyInvalid(t *testing.T) {
	v := NewAPIKeyValidator([]APIKeyEntry{
		{Key: "valid-key", Name: "service"},
	})

	_, err := v.Validate("wrong-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid API key")
}

func TestAPIKeyEmpty(t *testing.T) {
	v := NewAPIKeyValidator([]APIKeyEntry{
		{Key: "valid-key", Name: "service"},
	})

	_, err := v.Validate("")
	require.Error(t, err)
}

func TestAPIKeyNoKeys(t *testing.T) {
	v := NewAPIKeyValidator(nil)

	_, err := v.Validate("any-key")
	require.Error(t, err)
}

func TestAPIKeyConstantTime(t *testing.T) {
	// constant-time 比較のため、部分一致でも拒否される
	v := NewAPIKeyValidator([]APIKeyEntry{
		{Key: "abcdef123456", Name: "service"},
	})

	_, err := v.Validate("abcdef")
	require.Error(t, err)

	_, err = v.Validate("abcdef1234567") // 1文字多い
	require.Error(t, err)
}
