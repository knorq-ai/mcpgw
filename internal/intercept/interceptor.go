package intercept

import (
	"context"

	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

// Direction はメッセージの方向を表す。
type Direction int

const (
	DirClientToServer Direction = iota
	DirServerToClient
)

func (d Direction) String() string {
	if d == DirClientToServer {
		return "c2s"
	}
	return "s2c"
}

// Action は interceptor の判定結果を表す。
type Action int

const (
	ActionPass   Action = iota // メッセージを通過させる
	ActionBlock                // メッセージをブロックする
	ActionRedact               // メッセージを書き換えて通過させる
)

// Result は interceptor の処理結果。
type Result struct {
	Action        Action
	Reason        string         // ActionBlock 時のブロック理由
	RuleName      string         // ブロックしたルール名（アラート用）
	ErrorCode     int            // JSON-RPC エラーコード（0 → デフォルト -32600）
	ThreatType    string         // 脅威タイプ (例: "pii_detected", "injection_suspected")
	ThreatScore   float64        // 脅威スコア (0.0-1.0)
	ThreatDetails map[string]any // 脅威詳細
	RedactedBody  []byte         // ActionRedact 時の書き換え済みメッセージ
}

// Interceptor はメッセージを検査し、通過/ブロックを判定する。
type Interceptor interface {
	Intercept(ctx context.Context, dir Direction, msg *jsonrpc.Message, raw []byte) Result
}

// Chain は複数の Interceptor を順次実行する。
// 最初の ActionBlock で短絡する。
type Chain struct {
	interceptors []Interceptor
}

// NewChain は Interceptor チェーンを構築する。
func NewChain(interceptors ...Interceptor) *Chain {
	return &Chain{interceptors: interceptors}
}

// Process はチェーン内の全 Interceptor を順次実行する。
// ActionBlock を返した時点で短絡し、残りの Interceptor は実行されない。
// ActionRedact を返した場合は RedactedBody を後続の Interceptor に伝播し、
// チェーン全体の結果として ActionRedact を返す。
// ActionPass でも ThreatType が設定されている場合（検出のみモード等）は
// 最も高いスコアの脅威情報を保持して返す。
func (c *Chain) Process(ctx context.Context, dir Direction, msg *jsonrpc.Message, raw []byte) Result {
	best := Result{Action: ActionPass}
	currentRaw := raw
	for _, i := range c.interceptors {
		r := i.Intercept(ctx, dir, msg, currentRaw)
		if r.Action == ActionBlock {
			return r
		}
		if r.Action == ActionRedact && len(r.RedactedBody) > 0 {
			// 書き換え済みボディを後続の Interceptor に伝播する
			currentRaw = r.RedactedBody
			best = r
		} else if r.ThreatType != "" && r.ThreatScore > best.ThreatScore {
			// ActionPass でも脅威情報がある場合は最も高いスコアを保持
			best = r
		}
	}
	return best
}
