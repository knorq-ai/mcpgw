package proxy

import (
	"sync"
	"time"
)

// circuitState はサーキットブレーカーの状態。
type circuitState int

const (
	stateClosed   circuitState = iota // 正常 — リクエストを通過させる
	stateOpen                         // 遮断 — リクエストを即座に拒否する
	stateHalfOpen                     // 試行 — 1 リクエストのみ通過させる
)

// circuitBreaker は最小構成の 3 状態サーキットブレーカー。
// nil レシーバ安全: nil で全メソッドを呼び出しても panic しない（無効時 nil で使用可）。
type circuitBreaker struct {
	mu          sync.Mutex
	state       circuitState
	failures    int
	maxFailures int
	timeout     time.Duration
	openedAt    time.Time
}

// newCircuitBreaker は新しいサーキットブレーカーを生成する。
func newCircuitBreaker(maxFailures int, timeout time.Duration) *circuitBreaker {
	return &circuitBreaker{
		maxFailures: maxFailures,
		timeout:     timeout,
	}
}

// Allow はリクエストの通過を許可するかを返す。
// 拒否理由として open（CB trip）か halfOpen（試行中の保護的拒否）かを区別して返す。
func (cb *circuitBreaker) Allow() (bool, circuitState) {
	if cb == nil {
		return true, stateClosed
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case stateClosed:
		return true, stateClosed
	case stateOpen:
		if time.Since(cb.openedAt) >= cb.timeout {
			cb.state = stateHalfOpen
			return true, stateHalfOpen
		}
		return false, stateOpen
	case stateHalfOpen:
		// half-open 中は 1 リクエストのみ通過済み — 追加は拒否
		return false, stateHalfOpen
	}
	return true, stateClosed
}

// RecordSuccess は成功を記録する。
func (cb *circuitBreaker) RecordSuccess() {
	if cb == nil {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = stateClosed
}

// RecordFailure は失敗を記録する。
func (cb *circuitBreaker) RecordFailure() {
	if cb == nil {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	if cb.failures >= cb.maxFailures {
		cb.state = stateOpen
		cb.openedAt = time.Now()
	}
}
