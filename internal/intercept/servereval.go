package intercept

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	alertpkg "github.com/knorq-ai/mcpgw/internal/alert"
	"github.com/knorq-ai/mcpgw/internal/config"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/metrics"
	"github.com/knorq-ai/mcpgw/internal/policy"
	"github.com/knorq-ai/mcpgw/internal/servereval"
)

// ServerEvalInterceptor は S→C 方向の tools/list レスポンスを評価し、
// サーバーのリスクレベルに応じてブロックまたは通過を判定する。
type ServerEvalInterceptor struct {
	store   *servereval.Store
	cfg     config.ServerEvalConfig
	alerter *alertpkg.WebhookAlerter
}

// NewServerEvalInterceptor は新しい ServerEvalInterceptor を生成する。
func NewServerEvalInterceptor(store *servereval.Store, cfg config.ServerEvalConfig, alerter *alertpkg.WebhookAlerter) *ServerEvalInterceptor {
	return &ServerEvalInterceptor{store: store, cfg: cfg, alerter: alerter}
}

// Intercept は Interceptor インターフェースを実装する。
func (s *ServerEvalInterceptor) Intercept(ctx context.Context, dir Direction, msg *jsonrpc.Message, raw []byte) Result {
	// C→S はスキップ
	if dir == DirClientToServer {
		return Result{Action: ActionPass}
	}

	// tools/list レスポンスのみ処理
	if !s.isToolsListResponse(msg) {
		return Result{Action: ActionPass}
	}

	upstream := UpstreamFromContext(ctx)
	if upstream == "" {
		return Result{Action: ActionPass}
	}

	// キャッシュ済みの評価結果がある場合はそれを使用
	if existing := s.store.Get(upstream); existing != nil {
		return s.decide(existing)
	}

	// ツールリストを抽出
	tools := s.extractTools(msg.Result)
	if tools == nil {
		return Result{Action: ActionPass}
	}

	// リスク評価
	riskLevel, riskScore := servereval.ScoreTools(tools)

	// ステータス決定
	status := "pending"
	if s.isAllowlisted(upstream) {
		status = "approved"
	} else if s.isAutoApproved(riskLevel) {
		status = "approved"
	}

	info := &servereval.ServerInfo{
		Upstream:     upstream,
		Tools:        tools,
		RiskLevel:    riskLevel,
		RiskScore:    riskScore,
		Status:       status,
		DiscoveredAt: time.Now(),
		EvaluatedAt:  time.Now(),
	}
	s.store.Set(info)

	metrics.ServerEvaluationsTotal.WithLabelValues(riskLevel, status).Inc()

	slog.Info("server evaluated",
		"upstream", upstream,
		"risk_level", riskLevel,
		"risk_score", riskScore,
		"status", status,
		"tools", len(tools))

	// Webhook アラート（denied または pending の場合）
	if s.alerter != nil && status != "approved" {
		s.alerter.Alert(alertpkg.Payload{
			RuleName: "server-eval",
			Reason:   "server evaluation: " + status + " (risk=" + riskLevel + ")",
		})
	}

	return s.decide(info)
}

func (s *ServerEvalInterceptor) decide(info *servereval.ServerInfo) Result {
	switch info.Status {
	case "approved":
		return Result{Action: ActionPass}
	case "denied":
		if s.cfg.Mode == "audit" {
			return Result{Action: ActionPass}
		}
		return Result{
			Action:    ActionBlock,
			Reason:    "server denied by evaluation (risk=" + info.RiskLevel + ")",
			ErrorCode: -32600,
		}
	default: // "pending"
		if s.cfg.Mode == "enforce" {
			return Result{
				Action:    ActionBlock,
				Reason:    "server pending evaluation (risk=" + info.RiskLevel + ")",
				ErrorCode: -32600,
			}
		}
		return Result{Action: ActionPass}
	}
}

func (s *ServerEvalInterceptor) isToolsListResponse(msg *jsonrpc.Message) bool {
	if msg == nil || !msg.IsResponse() || len(msg.Result) == 0 {
		return false
	}
	// tools/list のレスポンスは result.tools 配列を持つ
	var result struct {
		Tools json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(msg.Result, &result) != nil || len(result.Tools) == 0 {
		return false
	}
	return result.Tools[0] == '['
}

func (s *ServerEvalInterceptor) extractTools(resultRaw json.RawMessage) []servereval.ToolInfo {
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if json.Unmarshal(resultRaw, &result) != nil {
		return nil
	}
	tools := make([]servereval.ToolInfo, len(result.Tools))
	for i, t := range result.Tools {
		tools[i] = servereval.ToolInfo{
			Name:      t.Name,
			RiskLevel: servereval.ScoreTool(t.Name),
		}
	}
	return tools
}

func (s *ServerEvalInterceptor) isAllowlisted(upstream string) bool {
	for _, entry := range s.cfg.Allowlist {
		if entry.Status != "approved" {
			continue
		}
		if policy.GlobMatch(entry.Upstream, upstream) {
			return true
		}
	}
	return false
}

func (s *ServerEvalInterceptor) isAutoApproved(riskLevel string) bool {
	for _, level := range s.cfg.AutoApprove.RiskLevels {
		if level == riskLevel {
			return true
		}
	}
	return false
}
