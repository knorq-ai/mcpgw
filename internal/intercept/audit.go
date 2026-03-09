package intercept

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	alertpkg "github.com/knorq-ai/mcpgw/internal/alert"
	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/auth"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

// AuditLogger はメッセージと最終判定結果を監査ログに記録する。
// Interceptor ではなく、pump から直接呼び出される。
type AuditLogger struct {
	logger  *audit.Logger
	alerter *alertpkg.WebhookAlerter
}

// AuditLoggerOption は AuditLogger のオプション。
type AuditLoggerOption func(*AuditLogger)

// WithAlerter は WebhookAlerter を AuditLogger に注入する。
func WithAlerter(a *alertpkg.WebhookAlerter) AuditLoggerOption {
	return func(al *AuditLogger) {
		al.alerter = a
	}
}

// NewAuditLogger は AuditLogger を生成する。
func NewAuditLogger(logger *audit.Logger, opts ...AuditLoggerOption) *AuditLogger {
	al := &AuditLogger{logger: logger}
	for _, opt := range opts {
		opt(al)
	}
	return al
}

// Log はメッセージと判定結果を監査ログに記録する。
func (a *AuditLogger) Log(ctx context.Context, dir Direction, msg *jsonrpc.Message, raw []byte, result Result) {
	action := "pass"
	switch result.Action {
	case ActionBlock:
		action = "block"
	case ActionRedact:
		action = "redact"
	}

	entry := &audit.Entry{
		Timestamp: time.Now(),
		Direction: dir.String(),
		Size:      len(raw),
		Action:    action,
		Reason:    result.Reason,
	}

	// コンテキストからリクエスト ID を取得
	if reqID := RequestIDFromContext(ctx); reqID != "" {
		entry.RequestID = reqID
	}

	if msg != nil {
		entry.Method = msg.Method
		entry.ID = strings.Trim(string(msg.ID), `"`)
		entry.Kind = kindString(msg.Kind())
		if msg.Method == "tools/call" && len(msg.Params) > 0 {
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if json.Unmarshal(msg.Params, &p) == nil && p.Name != "" {
				entry.ToolName = p.Name
				entry.ToolArgs = p.Arguments
			}
		}
	} else {
		entry.Kind = "unknown"
	}

	// 脅威情報を監査エントリに記録
	if result.ThreatType != "" {
		entry.ThreatType = result.ThreatType
		entry.ThreatScore = result.ThreatScore
		entry.ThreatDetails = result.ThreatDetails
	}

	if err := a.logger.Log(entry); err != nil {
		// fail-open: ログ書き込み失敗はプロキシを止めない
		slog.Error("audit log error", "error", err)
	}

	// ブロック時にアラート送信
	if result.Action == ActionBlock && a.alerter != nil {
		var subject string
		if id := auth.FromContext(ctx); id != nil {
			subject = id.Subject
		}
		ruleName := result.RuleName
		if ruleName == "" {
			ruleName = result.Reason
		}
		a.alerter.Alert(alertpkg.Payload{
			RuleName: ruleName,
			Method:   entry.Method,
			ToolName: entry.ToolName,
			Reason:   result.Reason,
			Subject:  subject,
		})
	}
}

func kindString(k jsonrpc.Kind) string {
	switch k {
	case jsonrpc.KindRequest:
		return "request"
	case jsonrpc.KindResponse:
		return "response"
	case jsonrpc.KindNotification:
		return "notification"
	default:
		return "unknown"
	}
}
