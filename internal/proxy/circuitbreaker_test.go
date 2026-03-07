package proxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cbAllow は Allow() の bool 部分のみを返すヘルパー。
func cbAllow(cb *circuitBreaker) bool {
	ok, _ := cb.Allow()
	return ok
}

func TestCircuitBreakerBasicFlow(t *testing.T) {
	cb := newCircuitBreaker(3, 100*time.Millisecond)

	// closed 状態 — 通過する
	assert.True(t, cbAllow(cb))
	cb.RecordSuccess()
	assert.True(t, cbAllow(cb))

	// 3 回失敗 → open
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	ok, state := cb.Allow()
	assert.False(t, ok, "open 状態ではリクエストを拒否する")
	assert.Equal(t, stateOpen, state, "拒否理由は open")

	// timeout 前は open のまま
	assert.False(t, cbAllow(cb))

	// timeout 後 → half-open → 1 リクエスト通過
	time.Sleep(150 * time.Millisecond)
	ok, state = cb.Allow()
	assert.True(t, ok, "timeout 後は half-open で 1 リクエスト通過する")
	assert.Equal(t, stateHalfOpen, state, "half-open 状態で通過")

	// half-open 中の追加リクエストは拒否
	ok, state = cb.Allow()
	assert.False(t, ok, "half-open 中は追加リクエストを拒否する")
	assert.Equal(t, stateHalfOpen, state, "拒否理由は halfOpen")

	// 成功 → closed に戻る
	cb.RecordSuccess()
	ok, state = cb.Allow()
	assert.True(t, ok, "成功後は closed に戻る")
	assert.Equal(t, stateClosed, state)
}

func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	cb := newCircuitBreaker(2, 50*time.Millisecond)

	// open にする
	cb.RecordFailure()
	cb.RecordFailure()
	require.False(t, cbAllow(cb))

	// timeout → half-open
	time.Sleep(60 * time.Millisecond)
	require.True(t, cbAllow(cb))

	// half-open で失敗 → 再び open
	cb.RecordFailure()
	ok, state := cb.Allow()
	assert.False(t, ok, "half-open で失敗すると再び open になる")
	assert.Equal(t, stateOpen, state)
}

func TestCircuitBreakerNilSafe(t *testing.T) {
	var cb *circuitBreaker

	// nil レシーバで panic しない
	ok, state := cb.Allow()
	assert.True(t, ok)
	assert.Equal(t, stateClosed, state)
	cb.RecordSuccess()
	cb.RecordFailure()
	assert.True(t, cbAllow(cb))
}

func TestCircuitBreakerSuccessResetsFailures(t *testing.T) {
	cb := newCircuitBreaker(3, time.Second)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // 失敗カウントリセット

	// 再度 2 回失敗してもまだ open にならない
	cb.RecordFailure()
	cb.RecordFailure()
	assert.True(t, cbAllow(cb), "成功で失敗カウントがリセットされる")

	// 3 回目で open
	cb.RecordFailure()
	assert.False(t, cbAllow(cb))
}
