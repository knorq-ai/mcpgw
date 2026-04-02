package audit

import "time"

// Entry は監査ログの1エントリを表す。
type Entry struct {
	Timestamp     time.Time      `json:"timestamp"`
	Direction     string         `json:"direction"` // "c2s" or "s2c"
	Method        string         `json:"method,omitempty"`
	ID            string         `json:"id,omitempty"`
	Kind          string         `json:"kind"`   // "request", "response", "notification", "unknown"
	Size          int            `json:"size"`   // 生バイト長
	Action        string         `json:"action"` // "pass" or "block"
	Reason        string         `json:"reason,omitempty"`
	Subject       string         `json:"subject,omitempty"`
	Upstream      string         `json:"upstream,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	ToolName      string         `json:"tool_name,omitempty"`
	ToolArgs      map[string]any `json:"tool_args,omitempty"`
	ThreatType    string         `json:"threat_type,omitempty"`    // 脅威タイプ (例: "pii_detected", "injection_suspected")
	ThreatScore   float64        `json:"threat_score,omitempty"`   // 脅威スコア (0.0-1.0)
	ThreatDetails map[string]any `json:"threat_details,omitempty"` // 脅威詳細
	TraceID       string         `json:"trace_id,omitempty"`       // OpenTelemetry trace ID
}
