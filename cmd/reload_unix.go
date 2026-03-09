//go:build !windows

package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/knorq-ai/mcpgw/internal/policy"
)

// EngineSwapper はポリシーエンジンをアトミックに入れ替えるインターフェース。
type EngineSwapper interface {
	SwapEngine(e *policy.Engine)
}

// watchPolicyReload は SIGHUP を監視し、ポリシーファイルを再読み込みして
// 全 EngineSwapper のエンジンをアトミックに入れ替える。
func watchPolicyReload(ctx context.Context, policyPath string, swappers ...EngineSwapper) {
	if policyPath == "" || len(swappers) == 0 {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				signal.Stop(ch)
				return
			case <-ch:
				pf, err := policy.Load(policyPath)
				if err != nil {
					slog.Error("policy reload failed", "error", err)
					continue
				}
				engine := policy.NewEngine(pf)
				for _, s := range swappers {
					s.SwapEngine(engine)
				}
				slog.Info("policy reloaded", "rules", len(pf.Rules))
			}
		}
	}()
}
