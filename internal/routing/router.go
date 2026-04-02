package routing

import (
	"encoding/json"
	"strings"

	"github.com/knorq-ai/mcpgw/internal/policy"
)

// Route は upstream へのルーティングルール。
type Route struct {
	MatchTools []string `yaml:"match_tools"` // ツール名 glob パターン
	Upstream   string   `yaml:"upstream"`    // 転送先 URL
}

// Router はツール名に基づいて upstream を決定する。
type Router struct {
	routes          []Route
	defaultUpstream string
}

// NewRouter は Router を構築する。
// routes が空の場合、全リクエストを defaultUpstream に転送する。
func NewRouter(routes []Route, defaultUpstream string) *Router {
	return &Router{
		routes:          routes,
		defaultUpstream: strings.TrimRight(defaultUpstream, "/"),
	}
}

// Resolve は JSON-RPC メソッドとパラメータから転送先 upstream を決定する。
// tools/call の場合はツール名でルートマッチングを行う。
// マッチしない場合はデフォルト upstream を返す。
func (r *Router) Resolve(method string, params json.RawMessage) string {
	if len(r.routes) == 0 {
		return r.defaultUpstream
	}

	// tools/call 以外はデフォルト upstream
	if method != "tools/call" {
		return r.defaultUpstream
	}

	toolName := policy.ExtractToolName(params)
	if toolName == "" {
		return r.defaultUpstream
	}

	for _, route := range r.routes {
		for _, pattern := range route.MatchTools {
			if policy.GlobMatch(pattern, toolName) {
				return strings.TrimRight(route.Upstream, "/")
			}
		}
	}

	return r.defaultUpstream
}

// Upstreams は全ルートの upstream URL リスト（重複なし）を返す。
// デフォルト upstream も含む。
func (r *Router) Upstreams() []string {
	seen := make(map[string]struct{})
	var result []string

	add := func(u string) {
		u = strings.TrimRight(u, "/")
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			result = append(result, u)
		}
	}

	add(r.defaultUpstream)
	for _, route := range r.routes {
		add(route.Upstream)
	}
	return result
}

// DefaultUpstream はデフォルト upstream URL を返す。
func (r *Router) DefaultUpstream() string {
	return r.defaultUpstream
}

// HasRoutes はルーティングルールが設定されているか返す。
func (r *Router) HasRoutes() bool {
	return len(r.routes) > 0
}
