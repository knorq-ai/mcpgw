package intercept

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/knorq-ai/mcpgw/internal/auth"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

func newTestMsg() *jsonrpc.Message {
	return &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test"}`),
	}
}

// frozenNow はテスト用に時刻を制御するヘルパー。
// atomic で安全に更新できる。
type frozenNow struct {
	val atomic.Value // time.Time
}

func newFrozenNow(t time.Time) *frozenNow {
	f := &frozenNow{}
	f.val.Store(t)
	return f
}

func (f *frozenNow) Now() time.Time {
	return f.val.Load().(time.Time)
}

func (f *frozenNow) Advance(d time.Duration) {
	f.val.Store(f.Now().Add(d))
}

func TestRateLimitWithinBurst(t *testing.T) {
	rl := NewRateLimitInterceptor(10, 3)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	// バースト内（3回）は全て通過
	for i := 0; i < 3; i++ {
		r := rl.Intercept(ctx, DirClientToServer, msg, nil)
		assert.Equal(t, ActionPass, r.Action, "request %d should pass", i)
	}
}

func TestRateLimitExceedsBurst(t *testing.T) {
	rl := NewRateLimitInterceptor(10, 3)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	// バースト消費
	for i := 0; i < 3; i++ {
		rl.Intercept(ctx, DirClientToServer, msg, nil)
	}

	// 4回目 → ブロック
	r := rl.Intercept(ctx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, r.Action)
	assert.Equal(t, -32429, r.ErrorCode)
	assert.Contains(t, r.Reason, "rate limit exceeded")
}

func TestRateLimitRefillOverTime(t *testing.T) {
	clock := newFrozenNow(time.Now())
	rl := newRateLimitInterceptor(10, 3, clock.Now)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	// バースト消費
	for i := 0; i < 3; i++ {
		rl.Intercept(ctx, DirClientToServer, msg, nil)
	}

	// 時間経過（0.5秒 → 5トークン補充、burst上限3なので3に）
	clock.Advance(500 * time.Millisecond)
	r := rl.Intercept(ctx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)
}

func TestRateLimitPerIdentity(t *testing.T) {
	rl := NewRateLimitInterceptor(1, 1)
	defer rl.Close()

	msg := newTestMsg()

	// alice がバースト消費
	aliceCtx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice"})
	r := rl.Intercept(aliceCtx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)
	r = rl.Intercept(aliceCtx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, r.Action)

	// bob は別バケット → 通過
	bobCtx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "bob"})
	r = rl.Intercept(bobCtx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)
}

func TestRateLimitAnonymous(t *testing.T) {
	rl := NewRateLimitInterceptor(1, 1)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	r := rl.Intercept(ctx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)

	// 未認証は "anonymous" バケットで一括管理
	r = rl.Intercept(ctx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, r.Action)
}

func TestRateLimitServerToClientPassthrough(t *testing.T) {
	rl := NewRateLimitInterceptor(1, 1)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	// S→C 方向は常に通過
	for i := 0; i < 10; i++ {
		r := rl.Intercept(ctx, DirServerToClient, msg, nil)
		assert.Equal(t, ActionPass, r.Action)
	}
}

func TestRateLimitSweep(t *testing.T) {
	clock := newFrozenNow(time.Now())
	rl := newRateLimitInterceptor(1, 1, clock.Now)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	// バケット作成
	rl.Intercept(ctx, DirClientToServer, msg, nil)

	rl.mu.Lock()
	assert.Len(t, rl.buckets, 1)
	rl.mu.Unlock()

	// 6 分後 → sweep で削除される
	clock.Advance(6 * time.Minute)
	rl.sweep()

	rl.mu.Lock()
	assert.Len(t, rl.buckets, 0)
	rl.mu.Unlock()
}

func TestRateLimitConcurrent(t *testing.T) {
	clock := newFrozenNow(time.Now())
	rl := newRateLimitInterceptor(1000, 100, clock.Now)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	var wg sync.WaitGroup
	var passCount int64

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rl.Intercept(ctx, DirClientToServer, msg, nil)
			if r.Action == ActionPass {
				atomic.AddInt64(&passCount, 1)
			}
		}()
	}
	wg.Wait()

	// frozen clock → トークン補充なし → バースト 100 が上限
	require.Equal(t, int64(100), passCount)
}

func TestRateLimitClockBackward(t *testing.T) {
	clock := newFrozenNow(time.Now())
	rl := newRateLimitInterceptor(10, 3, clock.Now)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	// 1 トークン消費
	r := rl.Intercept(ctx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)

	// クロック巻き戻し → トークンが減らないことを確認
	clock.Advance(-1 * time.Hour)
	r = rl.Intercept(ctx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action, "クロック巻き戻しでトークンが減ってはならない")
}

func TestRateLimitInvalidParams(t *testing.T) {
	// rate <= 0 → 1 に補正
	rl := NewRateLimitInterceptor(0, 0)
	defer rl.Close()

	msg := newTestMsg()
	ctx := context.Background()

	// burst は 1 に補正されるので1回は通過する
	r := rl.Intercept(ctx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionPass, r.Action)

	r = rl.Intercept(ctx, DirClientToServer, msg, nil)
	assert.Equal(t, ActionBlock, r.Action)
}
