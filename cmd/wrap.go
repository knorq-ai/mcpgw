package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/yuyamorita/mcpgw/internal/audit"
	"github.com/yuyamorita/mcpgw/internal/config"
	"github.com/yuyamorita/mcpgw/internal/intercept"
	"github.com/yuyamorita/mcpgw/internal/policy"
	"github.com/yuyamorita/mcpgw/internal/proxy"
)

var (
	wrapAuditLogPath string
	wrapPolicyPath   string
)

var wrapCmd = &cobra.Command{
	Use:   "wrap -- <command> [args...]",
	Short: "MCP サーバーを stdio プロキシでラップする",
	Long:  "指定コマンドを子プロセスとして起動し、stdin/stdout を傍受する。",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runWrap,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultLog := filepath.Join(home, ".mcpgw", "audit.jsonl")
	wrapCmd.Flags().StringVar(&wrapAuditLogPath, "audit-log", defaultLog, "監査ログファイルのパス")
	wrapCmd.Flags().StringVar(&wrapPolicyPath, "policy", "", "ポリシー YAML ファイルのパス")
	rootCmd.AddCommand(wrapCmd)
}

func runWrap(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 設定ファイル読み込み（ログ設定の適用のため）
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("mcpgw: %w", err)
	}
	setupLogging(cfg.Logging)

	// 監査ログの初期化
	logger, err := audit.NewLogger(wrapAuditLogPath, audit.DefaultMaxSize)
	if err != nil {
		slog.Warn("audit log init failed (continuing without audit)", "error", err)
	}
	if logger != nil {
		defer logger.Close()
	}

	// interceptor チェーン構築
	var interceptors []intercept.Interceptor
	var policyInterceptor *intercept.PolicyInterceptor
	if wrapPolicyPath != "" {
		pf, err := policy.Load(wrapPolicyPath)
		if err != nil {
			return fmt.Errorf("mcpgw: %w", err)
		}
		engine := policy.NewEngine(pf)
		policyInterceptor = intercept.NewPolicyInterceptor(engine)
		interceptors = append(interceptors, policyInterceptor)
		slog.Info("policy loaded", "rules", len(pf.Rules), "mode", pf.Mode)
	}
	chain := intercept.NewChain(interceptors...)

	// SIGHUP によるポリシーホットリロード
	watchPolicyReload(ctx, wrapPolicyPath, policyInterceptor)

	// 監査ロガー構築
	var auditLogger *intercept.AuditLogger
	if logger != nil {
		auditLogger = intercept.NewAuditLogger(logger)
	}

	// stdio プロキシ起動
	p := proxy.NewStdioProxy(args[0], args[1:], chain, auditLogger)
	if err := p.Run(ctx, os.Stdin, os.Stdout); err != nil {
		return fmt.Errorf("mcpgw: %w", err)
	}

	return nil
}
