//go:build windows

package cmd

import (
	"context"

	"github.com/knorq-ai/mcpgw/internal/policy"
)

// EngineSwapper はポリシーエンジンをアトミックに入れ替えるインターフェース。
type EngineSwapper interface {
	SwapEngine(e *policy.Engine)
}

// watchPolicyReload は Windows では no-op。SIGHUP が存在しないため。
func watchPolicyReload(_ context.Context, _ string, _ ...EngineSwapper) {}
