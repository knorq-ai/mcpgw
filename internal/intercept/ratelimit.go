package intercept

import (
	"context"
	"sync"
	"time"

	"github.com/yuyamorita/mcpgw/internal/auth"
	"github.com/yuyamorita/mcpgw/internal/jsonrpc"
)

// tokenBucket はトークンバケットアルゴリズムの状態。
type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

// RateLimitInterceptor は Identity ごとのレート制限を行う。
// C→S 方向のみ制限し、S→C は常に通過させる。
type RateLimitInterceptor struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens/sec
	burst   int
	now     func() time.Time // テスト用 DI
	stopCh  chan struct{}
	stopped chan struct{}
}

// NewRateLimitInterceptor は RateLimitInterceptor を生成し、sweep goroutine を開始する。
// rate は 0 より大きく、burst は 1 以上でなければならない。
func NewRateLimitInterceptor(rate float64, burst int) *RateLimitInterceptor {
	if rate <= 0 {
		rate = 1
	}
	if burst < 1 {
		burst = 1
	}
	return newRateLimitInterceptor(rate, burst, time.Now)
}

// newRateLimitInterceptor はテスト用 DI 付きコンストラクタ。
func newRateLimitInterceptor(rate float64, burst int, nowFn func() time.Time) *RateLimitInterceptor {
	r := &RateLimitInterceptor{
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

func (r *RateLimitInterceptor) Intercept(ctx context.Context, dir Direction, msg *jsonrpc.Message, _ []byte) Result {
	// S→C 方向は常に通過
	if dir == DirServerToClient {
		return Result{Action: ActionPass}
	}

	key := "anonymous"
	if id := auth.FromContext(ctx); id != nil && id.Subject != "" {
		key = id.Subject
	}

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

	// トークン補充（クロック巻き戻し時は elapsed=0 にクランプ）
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
		Reason:    "rate limit exceeded",
		ErrorCode: -32429,
	}
}

// sweepLoop は 1 分間隔で 5 分以上未使用のバケットを削除する。
func (r *RateLimitInterceptor) sweepLoop() {
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

func (r *RateLimitInterceptor) sweep() {
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
func (r *RateLimitInterceptor) Close() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
	<-r.stopped
}
