// Package plugin はインターセプタプラグインの抽象と管理を提供する。
package plugin

import (
	"github.com/knorq-ai/mcpgw/internal/intercept"
)

// Plugin はインターセプタとして動作するプラグインのインターフェース。
// Interceptor を埋め込み、名前・初期化・終了のライフサイクルメソッドを追加する。
type Plugin interface {
	intercept.Interceptor
	// Name はプラグインの一意な名前を返す。
	Name() string
	// Init は設定マップを受け取りプラグインを初期化する。
	Init(config map[string]any) error
	// Close はプラグインのリソースを解放する。
	Close() error
}
