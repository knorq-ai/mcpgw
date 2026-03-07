package intercept

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/knorq-ai/mcpgw/internal/auth"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/policy"
)

// PolicyInterceptor はポリシーエンジンに基づいてメッセージを通過/ブロックする。
type PolicyInterceptor struct {
	engine atomic.Pointer[policy.Engine]
}

// NewPolicyInterceptor は PolicyInterceptor を生成する。
func NewPolicyInterceptor(engine *policy.Engine) *PolicyInterceptor {
	p := &PolicyInterceptor{}
	p.engine.Store(engine)
	return p
}

// SwapEngine はポリシーエンジンをアトミックに入れ替える。
func (p *PolicyInterceptor) SwapEngine(e *policy.Engine) {
	p.engine.Store(e)
}

func (p *PolicyInterceptor) Intercept(ctx context.Context, dir Direction, msg *jsonrpc.Message, _ []byte) Result {
	// パース不能なメッセージ or S→C 方向は通過（fail-open）
	if msg == nil || dir == DirServerToClient {
		return Result{Action: ActionPass}
	}

	// メソッド名がないメッセージ（response 等）は通過
	if msg.Method == "" {
		return Result{Action: ActionPass}
	}

	engine := p.engine.Load()

	var subject string
	if id := auth.FromContext(ctx); id != nil {
		subject = id.Subject
	}
	decision := engine.Evaluate(msg.Method, msg.Params, subject)

	if !decision.Allow {
		// audit モードでは deny 判定でもブロックしない
		if engine.IsAuditMode() {
			return Result{Action: ActionPass}
		}
		return Result{
			Action: ActionBlock,
			Reason: fmt.Sprintf("denied by policy rule %q", decision.RuleName),
		}
	}

	return Result{Action: ActionPass}
}
