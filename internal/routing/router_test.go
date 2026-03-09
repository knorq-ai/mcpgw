package routing

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouterResolveToolMatch(t *testing.T) {
	r := NewRouter([]Route{
		{MatchTools: []string{"fs_*"}, Upstream: "http://localhost:8081"},
		{MatchTools: []string{"db_*"}, Upstream: "http://localhost:8082"},
	}, "http://localhost:8080")

	tests := []struct {
		name     string
		method   string
		params   json.RawMessage
		expected string
	}{
		{"fs tool", "tools/call", json.RawMessage(`{"name":"fs_read"}`), "http://localhost:8081"},
		{"db tool", "tools/call", json.RawMessage(`{"name":"db_query"}`), "http://localhost:8082"},
		{"unmatched tool", "tools/call", json.RawMessage(`{"name":"other_tool"}`), "http://localhost:8080"},
		{"non tools/call", "tools/list", nil, "http://localhost:8080"},
		{"empty params", "tools/call", nil, "http://localhost:8080"},
		{"no tool name", "tools/call", json.RawMessage(`{}`), "http://localhost:8080"},
		{"initialize", "initialize", nil, "http://localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, r.Resolve(tt.method, tt.params))
		})
	}
}

func TestRouterNoRoutes(t *testing.T) {
	r := NewRouter(nil, "http://localhost:8080")
	assert.Equal(t, "http://localhost:8080", r.Resolve("tools/call", json.RawMessage(`{"name":"anything"}`)))
	assert.False(t, r.HasRoutes())
}

func TestRouterUpstreams(t *testing.T) {
	r := NewRouter([]Route{
		{MatchTools: []string{"fs_*"}, Upstream: "http://localhost:8081"},
		{MatchTools: []string{"db_*"}, Upstream: "http://localhost:8082"},
		{MatchTools: []string{"cache_*"}, Upstream: "http://localhost:8081"}, // 重複
	}, "http://localhost:8080")

	upstreams := r.Upstreams()
	assert.Len(t, upstreams, 3)
	assert.Contains(t, upstreams, "http://localhost:8080")
	assert.Contains(t, upstreams, "http://localhost:8081")
	assert.Contains(t, upstreams, "http://localhost:8082")
}

func TestRouterTrailingSlash(t *testing.T) {
	r := NewRouter([]Route{
		{MatchTools: []string{"fs_*"}, Upstream: "http://localhost:8081/"},
	}, "http://localhost:8080/")

	assert.Equal(t, "http://localhost:8080", r.DefaultUpstream())
	assert.Equal(t, "http://localhost:8081", r.Resolve("tools/call", json.RawMessage(`{"name":"fs_read"}`)))
}

func TestRouterFirstMatchWins(t *testing.T) {
	r := NewRouter([]Route{
		{MatchTools: []string{"*"}, Upstream: "http://localhost:8081"},
		{MatchTools: []string{"db_*"}, Upstream: "http://localhost:8082"},
	}, "http://localhost:8080")

	// "*" が最初にマッチ
	assert.Equal(t, "http://localhost:8081", r.Resolve("tools/call", json.RawMessage(`{"name":"db_query"}`)))
}
