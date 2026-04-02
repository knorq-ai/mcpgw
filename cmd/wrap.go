package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/config"
	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/plugin"
	"github.com/knorq-ai/mcpgw/internal/policy"
	"github.com/knorq-ai/mcpgw/internal/proxy"
	"github.com/spf13/cobra"
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
	var defaultLog string
	if home, err := os.UserHomeDir(); err == nil {
		defaultLog = filepath.Join(home, ".mcpgw", "audit.jsonl")
	}
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

	// プラグインの読み込み
	if len(cfg.Plugins) > 0 {
		registry := plugin.NewRegistry()
		plugin.RegisterBuiltins(registry)
		plugins, pluginErr := plugin.LoadPlugins(registry, cfg.Plugins)
		if pluginErr != nil {
			return fmt.Errorf("mcpgw: %w", pluginErr)
		}
		for _, pl := range plugins {
			interceptors = append(interceptors, pl)
			slog.Info("plugin loaded", "name", pl.Name())
		}
		defer func() {
			for _, pl := range plugins {
				pl.Close()
			}
		}()
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
