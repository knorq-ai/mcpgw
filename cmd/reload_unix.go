//go:build !windows

package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/yuyamorita/mcpgw/internal/intercept"
	"github.com/yuyamorita/mcpgw/internal/policy"
)

// watchPolicyReload は SIGHUP を監視し、ポリシーファイルを再読み込みして
// PolicyInterceptor のエンジンをアトミックに入れ替える。
func watchPolicyReload(ctx context.Context, policyPath string, pi *intercept.PolicyInterceptor) {
	if policyPath == "" || pi == nil {
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
				pi.SwapEngine(engine)
				slog.Info("policy reloaded", "rules", len(pf.Rules))
			}
		}
	}()
}
