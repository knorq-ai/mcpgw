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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	alertpkg "github.com/knorq-ai/mcpgw/internal/alert"
	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/auth"
	"github.com/knorq-ai/mcpgw/internal/config"
	"github.com/knorq-ai/mcpgw/internal/dashboard"
	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/metrics"
	"github.com/knorq-ai/mcpgw/internal/plugin"
	"github.com/knorq-ai/mcpgw/internal/policy"
	"github.com/knorq-ai/mcpgw/internal/proxy"
	"github.com/knorq-ai/mcpgw/internal/routing"
	"github.com/knorq-ai/mcpgw/internal/telemetry"
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
	var defaultLog string
	if home, err := os.UserHomeDir(); err == nil {
		defaultLog = filepath.Join(home, ".mcpgw", "audit.jsonl")
	}

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

	if err := validateConfig(proxyUpstream, proxyTLSCert, proxyTLSKey); err != nil {
		return fmt.Errorf("mcpgw: %w", err)
	}

	// ルーティング設定のバリデーション
	for i, rc := range cfg.Routes {
		if len(rc.MatchTools) == 0 {
			return fmt.Errorf("mcpgw: routes[%d]: match_tools is required", i)
		}
		if rc.Upstream == "" {
			return fmt.Errorf("mcpgw: routes[%d]: upstream is required", i)
		}
		u, err := url.Parse(rc.Upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("mcpgw: routes[%d]: invalid upstream URL %q", i, rc.Upstream)
		}
	}

	// プラグイン名のバリデーション
	if len(cfg.Plugins) > 0 {
		validPlugins := map[string]bool{"pii": true, "injection": true, "schema": true}
		for i, pc := range cfg.Plugins {
			if pc.Name == "" {
				return fmt.Errorf("mcpgw: plugins[%d]: name is required", i)
			}
			if !validPlugins[pc.Name] {
				return fmt.Errorf("mcpgw: plugins[%d]: unknown plugin %q (available: pii, injection, schema)", i, pc.Name)
			}
		}
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

	// ツール単位レート制限
	if cfg.ToolRateLimit.RequestsPerMinute > 0 {
		burst := cfg.ToolRateLimit.Burst
		if burst <= 0 {
			burst = int(cfg.ToolRateLimit.RequestsPerMinute / 60.0)
			if burst < 1 {
				burst = 1
			}
		}
		trl := intercept.NewToolRateLimitInterceptor(cfg.ToolRateLimit.RequestsPerMinute, burst)
		defer trl.Close()
		interceptors = append(interceptors, trl)
		slog.Info("tool rate limit enabled", "rpm", cfg.ToolRateLimit.RequestsPerMinute, "burst", burst)
	}

	// ポリシー
	var policyInterceptor *intercept.PolicyInterceptor
	var responseInterceptor *intercept.ResponseInterceptor
	if proxyPolicyPath != "" {
		pf, err := policy.Load(proxyPolicyPath)
		if err != nil {
			return fmt.Errorf("mcpgw: %w", err)
		}
		engine := policy.NewEngine(pf)
		policyInterceptor = intercept.NewPolicyInterceptor(engine)
		interceptors = append(interceptors, policyInterceptor)

		// レスポンスインターセプター（response_patterns / allowed_tools が設定されている場合）
		if len(pf.ResponsePatterns) > 0 || len(pf.AllowedTools) > 0 {
			responseInterceptor = intercept.NewResponseInterceptor(engine)
			interceptors = append(interceptors, responseInterceptor)
			slog.Info("response interceptor enabled",
				"response_patterns", len(pf.ResponsePatterns),
				"allowed_tools", len(pf.AllowedTools))
		}

		slog.Info("policy loaded", "rules", len(pf.Rules), "mode", pf.Mode)
	}
	// Webhook アラート
	var webhookAlerter *alertpkg.WebhookAlerter
	if cfg.Alerting.WebhookURL != "" {
		dedupWindow := parseDuration(cfg.Alerting.DedupWindow, 5*time.Minute)
		webhookAlerter = alertpkg.NewWebhookAlerter(cfg.Alerting.WebhookURL, dedupWindow)
		defer webhookAlerter.Close()
		slog.Info("webhook alerting enabled", "url", cfg.Alerting.WebhookURL, "dedup_window", dedupWindow)
	}

	var auditLogger *intercept.AuditLogger
	if logger != nil {
		var auditOpts []intercept.AuditLoggerOption
		if webhookAlerter != nil {
			auditOpts = append(auditOpts, intercept.WithAlerter(webhookAlerter))
		}
		auditLogger = intercept.NewAuditLogger(logger, auditOpts...)
	}

	// 認証ミドルウェア構築
	authMiddleware, err := buildAuthMiddleware(cfg)
	if err != nil {
		return fmt.Errorf("mcpgw: %w", err)
	}

	// プラグインの読み込みと interceptor への追加
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

	// interceptor チェーンの構築（プラグイン追加後に生成）
	chain := intercept.NewChain(interceptors...)

	// セッション TTL
	sessionTTL := parseDuration(cfg.Session.TTL, 30*time.Minute)

	// トランスポート設定
	idleConnTimeout := parseDuration(cfg.Transport.IdleConnTimeout, 90*time.Second)
	requestTimeout := parseDuration(cfg.Transport.RequestTimeout, 60*time.Second)
	sseIdleTimeout := parseDuration(cfg.Transport.SSEIdleTimeout, 5*time.Minute)

	// サーキットブレーカー設定
	var cbCfg proxy.CircuitBreakerConfig
	if cfg.CircuitBreaker.MaxFailures > 0 {
		cbCfg = proxy.CircuitBreakerConfig{
			MaxFailures: cfg.CircuitBreaker.MaxFailures,
			Timeout:     parseDuration(cfg.CircuitBreaker.Timeout, 30*time.Second),
		}
	}

	// ルーティング設定
	var router *routing.Router
	if len(cfg.Routes) > 0 {
		var routes []routing.Route
		for _, rc := range cfg.Routes {
			routes = append(routes, routing.Route{
				MatchTools: rc.MatchTools,
				Upstream:   rc.Upstream,
			})
		}
		router = routing.NewRouter(routes, proxyUpstream)
		slog.Info("multi-upstream routing enabled", "routes", len(routes))
	}

	// DrainTimeout 設定
	drainTimeout := parseDuration(cfg.DrainTimeout, 30*time.Second)

	// HTTP プロキシ
	httpProxy := proxy.NewHTTPProxy(proxy.HTTPProxyConfig{
		Upstream:            proxyUpstream,
		Router:              router,
		Chain:               chain,
		Audit:               auditLogger,
		SessionTTL:          sessionTTL,
		MaxIdleConns:        cfg.Transport.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Transport.MaxIdleConnsPerHost,
		IdleConnTimeout:     idleConnTimeout,
		RequestTimeout:      requestTimeout,
		SSEIdleTimeout:      sseIdleTimeout,
		DrainTimeout:        drainTimeout,
		CircuitBreaker:      cbCfg,
	})
	defer httpProxy.Close()

	// ハンドラチェーン: CORS → telemetry → auth → HTTP proxy
	var handler http.Handler = httpProxy

	if authMiddleware != nil {
		handler = authMiddleware.Wrap(httpProxy)
	}

	// W3C traceparent ヘッダの伝播とトレース ID 生成
	handler = telemetry.Middleware(handler)

	if cors := proxy.NewCORSMiddleware(cfg.CORS.AllowedOrigins); cors != nil {
		handler = cors.Wrap(handler)
	}

	srv := &http.Server{
		Addr:              proxyListen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// ポリシーホットリロード用のスワッパー
	var swappers []EngineSwapper
	if policyInterceptor != nil {
		swappers = append(swappers, policyInterceptor)
	}
	if responseInterceptor != nil {
		swappers = append(swappers, responseInterceptor)
	}

	// メインサーバー終了時に管理サーバーも停止するための cancel
	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	// 管理サーバー（メトリクス + ヘルスチェック）
	if cfg.Metrics.Addr != "" {
		metrics.Register()
		mgmtMux := http.NewServeMux()
		mgmtMux.Handle("/metrics", promhttp.Handler())
		mgmtMux.HandleFunc("/healthz", healthHandler)
		mgmtMux.HandleFunc("/readyz", readyzHandler(httpProxy))

		// ダッシュボード
		var pp dashboard.PolicyProvider
		if policyInterceptor != nil {
			pp = policyInterceptor
		}
		var dashSwappers []dashboard.EngineSwapper
		for _, s := range swappers {
			dashSwappers = append(dashSwappers, s)
		}
		dashboard.Register(mgmtMux, dashboard.Config{
			AuditLogPath:   proxyAuditLogPath,
			StatusProvider: httpProxy,
			PolicyProvider: pp,
			PolicyPath:     proxyPolicyPath,
			EngineSwappers: dashSwappers,
		})

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
			<-srvCtx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			mgmtSrv.Shutdown(shutdownCtx)
		}()
	}

	// SIGHUP によるポリシーホットリロード
	watchPolicyReload(ctx, proxyPolicyPath, swappers...)

	// graceful shutdown（drain → shutdown の順序）
	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		slog.Info("shutting down (drain phase)")
		httpProxy.Drain()
		slog.Info("drain complete, shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
		close(shutdownDone)
	}()

	if proxyTLSCert != "" && proxyTLSKey != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		slog.Info("proxy listening (TLS)", "addr", proxyListen, "upstream", proxyUpstream)
		if err := srv.ListenAndServeTLS(proxyTLSCert, proxyTLSKey); err != http.ErrServerClosed {
			srvCancel() // 管理サーバーも停止
			return fmt.Errorf("mcpgw: %w", err)
		}
	} else {
		slog.Info("proxy listening", "addr", proxyListen, "upstream", proxyUpstream)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			srvCancel() // 管理サーバーも停止
			return fmt.Errorf("mcpgw: %w", err)
		}
	}

	<-shutdownDone
	return nil
}

// healthHandler は /healthz エンドポイントのハンドラ（liveness probe）。
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// readyzHandler は /readyz エンドポイントのハンドラ（readiness probe）。
// upstream への到達性を確認し、不能時は 503 を返す。
func readyzHandler(hp *proxy.HTTPProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !hp.UpstreamReady() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "unavailable"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
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

		// RolesClaim 設定
		if cfg.Auth.JWT.RolesClaim != "" {
			jwtCfg.RolesClaim = cfg.Auth.JWT.RolesClaim
		}

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

	// OAuth 2.1 / JWKS
	var middlewareOpts []auth.MiddlewareOption
	if cfg.Auth.OAuth.JWKSURL != "" {
		oauthValidator, oauthErr := auth.NewOAuthValidator(auth.OAuthConfig{
			JWKSURL:     cfg.Auth.OAuth.JWKSURL,
			Issuer:      cfg.Auth.OAuth.Issuer,
			Audience:    cfg.Auth.OAuth.Audience,
			ResourceURL: cfg.Auth.OAuth.ResourceURL,
		})
		if oauthErr != nil {
			return nil, oauthErr
		}
		middlewareOpts = append(middlewareOpts, auth.WithOAuth(oauthValidator))
		slog.Info("OAuth 2.1 auth enabled", "jwks_url", cfg.Auth.OAuth.JWKSURL, "issuer", cfg.Auth.OAuth.Issuer)
	}

	if jwtValidator == nil && apikeyValidator == nil && len(middlewareOpts) == 0 {
		return nil, nil
	}

	return auth.NewMiddleware(jwtValidator, apikeyValidator, middlewareOpts...), nil
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

// validateConfig は起動時に設定値を検証する。
func validateConfig(upstream, tlsCert, tlsKey string) error {
	u, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("upstream URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("upstream URL must have a host")
	}
	if tlsCert != "" {
		if _, err := os.Stat(tlsCert); err != nil {
			return fmt.Errorf("TLS cert file: %w", err)
		}
	}
	if tlsKey != "" {
		if _, err := os.Stat(tlsKey); err != nil {
			return fmt.Errorf("TLS key file: %w", err)
		}
	}
	return nil
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
