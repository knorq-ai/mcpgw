package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/auth"
	"github.com/knorq-ai/mcpgw/internal/config"
	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/metrics"
	"github.com/knorq-ai/mcpgw/internal/policy"
	"github.com/knorq-ai/mcpgw/internal/proxy"
)

var (
	proxyUpstream     string
	proxyListen       string
	proxyPolicyPath   string
	proxyAuditLogPath string
	proxyJWTAlgorithm string
	proxyJWTSecret    string
	proxyJWTPubkey    string
	proxyAPIKeys      string
	proxyTLSCert      string
	proxyTLSKey       string
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "HTTP リバースプロキシとして MCP サーバーをプロキシする",
	Long:  "MCP Streamable HTTP トランスポートのリバースプロキシ。認証・ポリシー・監査ログを適用する。",
	RunE:  runProxy,
}

func init() {
	home, _ := os.UserHomeDir()
	defaultLog := filepath.Join(home, ".mcpgw", "audit.jsonl")

	proxyCmd.Flags().StringVar(&proxyUpstream, "upstream", "", "upstream MCP サーバーの URL")
	proxyCmd.Flags().StringVar(&proxyListen, "listen", ":9090", "リッスンアドレス")
	proxyCmd.Flags().StringVar(&proxyPolicyPath, "policy", "", "ポリシー YAML ファイルのパス")
	proxyCmd.Flags().StringVar(&proxyAuditLogPath, "audit-log", defaultLog, "監査ログファイルのパス")
	proxyCmd.Flags().StringVar(&proxyJWTAlgorithm, "auth-jwt-algorithm", "", "JWT アルゴリズム (HS256, RS256, ES256)")
	proxyCmd.Flags().StringVar(&proxyJWTSecret, "auth-jwt-secret", "", "JWT 共有シークレット (HS256 用、env: MCPGW_JWT_SECRET)")
	proxyCmd.Flags().StringVar(&proxyJWTPubkey, "auth-jwt-pubkey", "", "JWT 公開鍵ファイルのパス (RS256/ES256 用)")
	proxyCmd.Flags().StringVar(&proxyAPIKeys, "auth-apikeys", "", "API キー (カンマ区切り、env: MCPGW_API_KEYS)")
	proxyCmd.Flags().StringVar(&proxyTLSCert, "tls-cert", "", "TLS 証明書ファイルのパス")
	proxyCmd.Flags().StringVar(&proxyTLSKey, "tls-key", "", "TLS 秘密鍵ファイルのパス")

	rootCmd.AddCommand(proxyCmd)
}

func runProxy(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 設定ファイル読み込み
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("mcpgw: %w", err)
	}
	mergeConfig(cmd, cfg)

	// ログ初期化
	setupLogging(cfg.Logging)

	// upstream が未指定の場合はエラー
	if proxyUpstream == "" {
		return fmt.Errorf("mcpgw: --upstream or config upstream is required")
	}

	// TLS フラグのバリデーション（cert/key は両方指定が必須）
	if (proxyTLSCert != "") != (proxyTLSKey != "") {
		return fmt.Errorf("mcpgw: --tls-cert and --tls-key must both be specified")
	}

	// 監査ログ
	logger, err := audit.NewLogger(proxyAuditLogPath, audit.DefaultMaxSize)
	if err != nil {
		slog.Warn("audit log init failed (continuing without audit)", "error", err)
	}
	if logger != nil {
		defer logger.Close()
	}

	// interceptor チェーン
	var interceptors []intercept.Interceptor

	// レート制限（先頭 — 高速にリジェクト）
	if cfg.RateLimit.RequestsPerSecond > 0 {
		burst := cfg.RateLimit.Burst
		if burst <= 0 {
			burst = int(cfg.RateLimit.RequestsPerSecond)
		}
		rl := intercept.NewRateLimitInterceptor(cfg.RateLimit.RequestsPerSecond, burst)
		defer rl.Close()
		interceptors = append(interceptors, rl)
		slog.Info("rate limit enabled", "rps", cfg.RateLimit.RequestsPerSecond, "burst", burst)
	}

	// ポリシー
	var policyInterceptor *intercept.PolicyInterceptor
	if proxyPolicyPath != "" {
		pf, err := policy.Load(proxyPolicyPath)
		if err != nil {
			return fmt.Errorf("mcpgw: %w", err)
		}
		engine := policy.NewEngine(pf)
		policyInterceptor = intercept.NewPolicyInterceptor(engine)
		interceptors = append(interceptors, policyInterceptor)
		slog.Info("policy loaded", "rules", len(pf.Rules), "mode", pf.Mode)
	}
	chain := intercept.NewChain(interceptors...)

	var auditLogger *intercept.AuditLogger
	if logger != nil {
		auditLogger = intercept.NewAuditLogger(logger)
	}

	// 認証ミドルウェア構築
	authMiddleware, err := buildAuthMiddleware(cfg)
	if err != nil {
		return fmt.Errorf("mcpgw: %w", err)
	}

	// セッション TTL
	sessionTTL := parseDuration(cfg.Session.TTL, 30*time.Minute)

	// トランスポート設定
	idleConnTimeout := parseDuration(cfg.Transport.IdleConnTimeout, 90*time.Second)

	// HTTP プロキシ
	httpProxy := proxy.NewHTTPProxy(proxy.HTTPProxyConfig{
		Upstream:            proxyUpstream,
		Chain:               chain,
		Audit:               auditLogger,
		SessionTTL:          sessionTTL,
		MaxIdleConns:        cfg.Transport.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Transport.MaxIdleConnsPerHost,
		IdleConnTimeout:     idleConnTimeout,
	})
	defer httpProxy.Close()

	// ハンドラチェーン: CORS → auth → HTTP proxy
	var handler http.Handler = httpProxy

	if authMiddleware != nil {
		handler = authMiddleware.Wrap(httpProxy)
	}

	if cors := proxy.NewCORSMiddleware(cfg.CORS.AllowedOrigins); cors != nil {
		handler = cors.Wrap(handler)
	}

	srv := &http.Server{
		Addr:              proxyListen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// 管理サーバー（メトリクス + ヘルスチェック）
	if cfg.Metrics.Addr != "" {
		metrics.Register()
		mgmtMux := http.NewServeMux()
		mgmtMux.Handle("/metrics", promhttp.Handler())
		mgmtMux.HandleFunc("/healthz", healthHandler)
		mgmtSrv := &http.Server{
			Addr:              cfg.Metrics.Addr,
			Handler:           mgmtMux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			slog.Info("management server listening", "addr", cfg.Metrics.Addr)
			if err := mgmtSrv.ListenAndServe(); err != http.ErrServerClosed {
				slog.Error("management server error", "error", err)
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			mgmtSrv.Shutdown(shutdownCtx)
		}()
	}

	// SIGHUP によるポリシーホットリロード
	watchPolicyReload(ctx, proxyPolicyPath, policyInterceptor)

	// graceful shutdown
	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	if proxyTLSCert != "" && proxyTLSKey != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		slog.Info("proxy listening (TLS)", "addr", proxyListen, "upstream", proxyUpstream)
		if err := srv.ListenAndServeTLS(proxyTLSCert, proxyTLSKey); err != http.ErrServerClosed {
			return fmt.Errorf("mcpgw: %w", err)
		}
	} else {
		slog.Info("proxy listening", "addr", proxyListen, "upstream", proxyUpstream)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("mcpgw: %w", err)
		}
	}

	return nil
}

// healthHandler は /healthz エンドポイントのハンドラ。
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// mergeConfig は CLI フラグが明示的に設定されていない場合に設定ファイルの値を適用する。
func mergeConfig(cmd *cobra.Command, cfg *config.Config) {
	if !cmd.Flags().Changed("upstream") && cfg.Upstream != "" {
		proxyUpstream = cfg.Upstream
	}
	if !cmd.Flags().Changed("listen") && cfg.Listen != "" {
		proxyListen = cfg.Listen
	}
	if !cmd.Flags().Changed("policy") && cfg.Policy != "" {
		proxyPolicyPath = cfg.Policy
	}
	if !cmd.Flags().Changed("audit-log") && cfg.AuditLog != "" {
		proxyAuditLogPath = cfg.AuditLog
	}
	if !cmd.Flags().Changed("auth-jwt-algorithm") && cfg.Auth.JWT.Algorithm != "" {
		proxyJWTAlgorithm = cfg.Auth.JWT.Algorithm
	}
	if !cmd.Flags().Changed("auth-jwt-secret") && cfg.Auth.JWT.Secret != "" {
		proxyJWTSecret = cfg.Auth.JWT.Secret
	}
	if !cmd.Flags().Changed("auth-jwt-pubkey") && cfg.Auth.JWT.PubkeyFile != "" {
		proxyJWTPubkey = cfg.Auth.JWT.PubkeyFile
	}
	if !cmd.Flags().Changed("auth-apikeys") && len(cfg.Auth.APIKeys) > 0 {
		var keys []string
		for _, k := range cfg.Auth.APIKeys {
			keys = append(keys, k.Key)
		}
		proxyAPIKeys = strings.Join(keys, ",")
	}
	if !cmd.Flags().Changed("tls-cert") && cfg.TLS.CertFile != "" {
		proxyTLSCert = cfg.TLS.CertFile
	}
	if !cmd.Flags().Changed("tls-key") && cfg.TLS.KeyFile != "" {
		proxyTLSKey = cfg.TLS.KeyFile
	}
}

// buildAuthMiddleware はフラグと環境変数から認証ミドルウェアを構築する。
func buildAuthMiddleware(cfg *config.Config) (*auth.Middleware, error) {
	var jwtValidator *auth.JWTValidator
	var apikeyValidator *auth.APIKeyValidator

	// JWT
	algo := proxyJWTAlgorithm
	if algo != "" {
		jwtCfg := auth.JWTConfig{Algorithm: algo}

		switch algo {
		case "HS256":
			secret := proxyJWTSecret
			if secret == "" {
				secret = os.Getenv("MCPGW_JWT_SECRET")
			}
			if secret == "" {
				return nil, fmt.Errorf("HS256 requires --auth-jwt-secret or MCPGW_JWT_SECRET")
			}
			jwtCfg.Secret = []byte(secret)

		case "RS256", "ES256":
			if proxyJWTPubkey == "" {
				return nil, fmt.Errorf("%s requires --auth-jwt-pubkey", algo)
			}
			pubKey, err := loadPublicKey(proxyJWTPubkey, algo)
			if err != nil {
				return nil, err
			}
			jwtCfg.PublicKey = pubKey
		}

		v, err := auth.NewJWTValidator(jwtCfg)
		if err != nil {
			return nil, err
		}
		jwtValidator = v
		slog.Info("JWT auth enabled", "algorithm", algo)
	}

	// API keys
	keysStr := proxyAPIKeys
	if keysStr == "" {
		keysStr = os.Getenv("MCPGW_API_KEYS")
	}
	if keysStr != "" {
		keys := strings.Split(keysStr, ",")
		var entries []auth.APIKeyEntry
		for i, k := range keys {
			k = strings.TrimSpace(k)
			if k != "" {
				entries = append(entries, auth.APIKeyEntry{
					Key:  k,
					Name: fmt.Sprintf("apikey-%d", i),
				})
			}
		}
		apikeyValidator = auth.NewAPIKeyValidator(entries)
		slog.Info("API key auth enabled", "keys", len(entries))
	}

	if jwtValidator == nil && apikeyValidator == nil {
		return nil, nil
	}

	return auth.NewMiddleware(jwtValidator, apikeyValidator), nil
}

// loadPublicKey は PEM ファイルから公開鍵を読み込む。
func loadPublicKey(path string, algo string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key %s: %w", path, err)
	}

	switch algo {
	case "RS256":
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("expected RSA public key in %s", path)
		}
	case "ES256":
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("expected ECDSA public key in %s", path)
		}
	}

	return pub, nil
}

// parseDuration は文字列を time.Duration に変換する。
// 空文字列の場合は fallback を返す。パースエラーは警告して fallback を返す。
func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		slog.Warn("invalid duration, using default", "value", s, "default", fallback)
		return fallback
	}
	return d
}
