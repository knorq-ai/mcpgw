package memory

// state パッケージのインターフェースに対するコンパイル時適合チェック。

import (
	"time"

	"github.com/knorq-ai/mcpgw/internal/state"
)

var (
	_ state.SessionStore        = (*SessionStore)(nil)
	_ state.RateLimitStore      = (*RateLimitStore)(nil)
	_ state.CircuitBreakerStore = (*CircuitBreakerStore)(nil)
)

// 未使用インポートを防ぐためのダミー参照。
var _ = time.Second
