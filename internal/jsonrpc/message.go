package jsonrpc

import "encoding/json"

// JSON-RPC 2.0 メッセージ。
// Params, Result は json.RawMessage のまま保持し、再シリアライズを回避する。
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ErrorObject    `json:"error,omitempty"`
}

// ErrorObject は JSON-RPC 2.0 のエラーオブジェクト。
type ErrorObject struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Kind はメッセージの種類を表す。
type Kind int

const (
	KindRequest      Kind = iota // id あり + method あり
	KindResponse                 // id あり + method なし + result/error
	KindNotification             // id なし + method あり
	KindUnknown
)

// Kind はメッセージの種類を判定する。
func (m *Message) Kind() Kind {
	hasID := len(m.ID) > 0 && string(m.ID) != "null"
	hasMethod := m.Method != ""

	switch {
	case hasID && hasMethod:
		return KindRequest
	case hasID && !hasMethod:
		return KindResponse
	case !hasID && hasMethod:
		return KindNotification
	default:
		return KindUnknown
	}
}

// IsRequest は ID とメソッド両方を持つ場合に true を返す。
func (m *Message) IsRequest() bool {
	return m.Kind() == KindRequest
}

// IsResponse は ID を持ちメソッドを持たない場合に true を返す。
func (m *Message) IsResponse() bool {
	return m.Kind() == KindResponse
}

// IsNotification は ID を持たずメソッドを持つ場合に true を返す。
func (m *Message) IsNotification() bool {
	return m.Kind() == KindNotification
}
