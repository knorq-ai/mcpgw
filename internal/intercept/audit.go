package intercept

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/knorq-ai/mcpgw/internal/audit"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

// AuditLogger はメッセージと最終判定結果を監査ログに記録する。
// Interceptor ではなく、pump から直接呼び出される。
type AuditLogger struct {
	logger *audit.Logger
}

// NewAuditLogger は AuditLogger を生成する。
func NewAuditLogger(logger *audit.Logger) *AuditLogger {
	return &AuditLogger{logger: logger}
}

// Log はメッセージと判定結果を監査ログに記録する。
func (a *AuditLogger) Log(ctx context.Context, dir Direction, msg *jsonrpc.Message, raw []byte, result Result) {
	action := "pass"
	if result.Action == ActionBlock {
		action = "block"
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
	} else {
		entry.Kind = "unknown"
	}

	if err := a.logger.Log(entry); err != nil {
		// fail-open: ログ書き込み失敗はプロキシを止めない
		slog.Error("audit log error", "error", err)
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
