package intercept

import (
	"context"

	"github.com/yuyamorita/mcpgw/internal/jsonrpc"
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
	ActionPass  Action = iota // メッセージを通過させる
	ActionBlock              // メッセージをブロックする
)

// Result は interceptor の処理結果。
type Result struct {
	Action    Action
	Reason    string // ActionBlock 時のブロック理由
	ErrorCode int    // JSON-RPC エラーコード（0 → デフォルト -32600）
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
// 監査ログは chain 外部（pump 内）で最終判定結果を記録する。
func (c *Chain) Process(ctx context.Context, dir Direction, msg *jsonrpc.Message, raw []byte) Result {
	for _, i := range c.interceptors {
		r := i.Intercept(ctx, dir, msg, raw)
		if r.Action == ActionBlock {
			return r
		}
	}
	return Result{Action: ActionPass}
}
