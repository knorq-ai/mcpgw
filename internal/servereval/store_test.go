package servereval

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreGetSetList(t *testing.T) {
	s := NewStore()

	assert.Nil(t, s.Get("http://a"))
	assert.Empty(t, s.List())

	info := &ServerInfo{
		Upstream:     "http://a",
		RiskLevel:    "low",
		RiskScore:    0.2,
		Status:       "approved",
		DiscoveredAt: time.Now(),
		EvaluatedAt:  time.Now(),
	}
	s.Set(info)

	got := s.Get("http://a")
	require.NotNil(t, got)
	assert.Equal(t, "low", got.RiskLevel)

	list := s.List()
	assert.Len(t, list, 1)
}

func TestStoreUpdateStatus(t *testing.T) {
	s := NewStore()

	assert.False(t, s.UpdateStatus("http://x", "approved"))

	s.Set(&ServerInfo{Upstream: "http://x", Status: "pending"})
	assert.True(t, s.UpdateStatus("http://x", "denied"))
	assert.Equal(t, "denied", s.Get("http://x").Status)
}
