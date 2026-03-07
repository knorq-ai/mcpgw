package audit

import "time"

// Entry は監査ログの1エントリを表す。
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"` // "c2s" or "s2c"
	Method    string    `json:"method,omitempty"`
	ID        string    `json:"id,omitempty"`
	Kind      string    `json:"kind"` // "request", "response", "notification", "unknown"
	Size      int       `json:"size"` // 生バイト長
	Action    string    `json:"action"` // "pass" or "block"
	Reason    string    `json:"reason,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
}
