// Package memory は state.SessionStore / state.RateLimitStore / state.CircuitBreakerStore の
// インメモリ実装を提供する。単一プロセス構成向け。
package memory

import "time"

// tokenBucket はトークンバケットアルゴリズムの内部状態。
type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}
