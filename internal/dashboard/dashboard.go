package dashboard

import (
	"net/http"

	"github.com/knorq-ai/mcpgw/internal/policy"
	"github.com/knorq-ai/mcpgw/internal/servereval"
)

// StatusProvider はシステムステータス情報を提供する。
type StatusProvider interface {
	UpstreamReady() bool
	CircuitBreakerState() string
	ActiveSessionCount() int
	Upstream() string
}

// PolicyProvider はポリシー情報を提供する。
type PolicyProvider interface {
	PolicyFile() *policy.PolicyFile
}

// EngineSwapper はポリシーエンジンをアトミックに入れ替えるインターフェース。
type EngineSwapper interface {
	SwapEngine(e *policy.Engine)
}

// Config はダッシュボードの設定。
type Config struct {
	AuditLogPath   string
	StatusProvider StatusProvider
	PolicyProvider PolicyProvider
	PolicyPath     string               // ポリシーファイルパス（PUT /api/policy 用）
	EngineSwappers []EngineSwapper      // ホットリロード用
	ServerEvalStore *servereval.Store   // サーバー評価ストア（nil の場合は無効）
}

// Register はダッシュボード関連のハンドラを mux に登録する。
func Register(mux *http.ServeMux, cfg Config) {
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/api/audit", handleAudit(cfg.AuditLogPath))
	mux.HandleFunc("/api/policy/test", handlePolicyTest(cfg.PolicyProvider))
	mux.HandleFunc("/api/policy", handlePolicyRoute(cfg))
	mux.HandleFunc("/api/status", handleStatus(cfg.StatusProvider))

	// サーバー評価 API
	if cfg.ServerEvalStore != nil {
		mux.HandleFunc("/api/servers", handleServers(cfg.ServerEvalStore))
		mux.HandleFunc("/api/servers/approve", handleServerAction(cfg.ServerEvalStore, "approved"))
		mux.HandleFunc("/api/servers/deny", handleServerAction(cfg.ServerEvalStore, "denied"))
	}

	// Analytics API
	mux.HandleFunc("/api/analytics/by-server", handleAnalytics(cfg.AuditLogPath, "upstream"))
	mux.HandleFunc("/api/analytics/by-user", handleAnalytics(cfg.AuditLogPath, "subject"))
	mux.HandleFunc("/api/analytics/by-tool", handleAnalytics(cfg.AuditLogPath, "tool"))
	mux.HandleFunc("/api/analytics/threats", handleAnalytics(cfg.AuditLogPath, "threat"))

	mux.Handle("/", spaHandler())
}

// handlePolicyRoute は /api/policy に対して GET と PUT を振り分けるハンドラ。
func handlePolicyRoute(cfg Config) http.HandlerFunc {
	getHandler := handlePolicy(cfg.PolicyProvider)
	putHandler := handlePolicyUpdate(cfg.PolicyPath, cfg.PolicyProvider, cfg.EngineSwappers)
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getHandler(w, r)
		case http.MethodPut:
			putHandler(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}
