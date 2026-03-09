package intercept

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/knorq-ai/mcpgw/internal/auth"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/policy"
)

// ToolRateLimitInterceptor は subject:tool_name 単位のレート制限を行う。
// tools/call メソッドの C→S 方向のみ制限する。
type ToolRateLimitInterceptor struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens/sec
	burst   int
	now     func() time.Time
	stopCh  chan struct{}
	stopped chan struct{}
}

// NewToolRateLimitInterceptor は ToolRateLimitInterceptor を生成する。
// rpm は分あたりのリクエスト数。
func NewToolRateLimitInterceptor(rpm float64, burst int) *ToolRateLimitInterceptor {
	if rpm <= 0 {
		rpm = 60
	}
	rate := rpm / 60.0 // tokens/sec に変換
	if burst < 1 {
		burst = int(rpm / 60.0)
		if burst < 1 {
			burst = 1
		}
	}
	return newToolRateLimitInterceptor(rate, burst, time.Now)
}

func newToolRateLimitInterceptor(rate float64, burst int, nowFn func() time.Time) *ToolRateLimitInterceptor {
	r := &ToolRateLimitInterceptor{
		buckets: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
		now:     nowFn,
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go r.sweepLoop()
	return r
}

func (r *ToolRateLimitInterceptor) Intercept(ctx context.Context, dir Direction, msg *jsonrpc.Message, raw []byte) Result {
	// S→C 方向は常に通過
	if dir == DirServerToClient {
		return Result{Action: ActionPass}
	}

	// tools/call 以外は通過
	if msg == nil || msg.Method != "tools/call" {
		return Result{Action: ActionPass}
	}

	// ツール名を抽出
	toolName := policy.ExtractToolName(msg.Params)
	if toolName == "" {
		return Result{Action: ActionPass}
	}

	// subject を取得
	subject := "anonymous"
	if id := auth.FromContext(ctx); id != nil && id.Subject != "" {
		subject = id.Subject
	}

	key := subject + ":" + toolName

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	b, ok := r.buckets[key]
	if !ok {
		b = &tokenBucket{
			tokens:   float64(r.burst),
			lastTime: now,
		}
		r.buckets[key] = b
	}

	elapsed := now.Sub(b.lastTime).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.tokens += elapsed * r.rate
	if b.tokens > float64(r.burst) {
		b.tokens = float64(r.burst)
	}
	b.lastTime = now

	if b.tokens >= 1 {
		b.tokens--
		return Result{Action: ActionPass}
	}

	return Result{
		Action:    ActionBlock,
		Reason:    fmt.Sprintf("tool rate limit exceeded for %s", toolName),
		ErrorCode: -32429,
	}
}

func (r *ToolRateLimitInterceptor) sweepLoop() {
	defer close(r.stopped)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.sweep()
		}
	}
}

func (r *ToolRateLimitInterceptor) sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-5 * time.Minute)
	for k, b := range r.buckets {
		if b.lastTime.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
}

// Close は sweep goroutine を停止する。
func (r *ToolRateLimitInterceptor) Close() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
	<-r.stopped
}
