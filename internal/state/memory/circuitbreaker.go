package memory

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

// circuitEntry は upstream 単位のサーキットブレーカー内部状態。
type circuitEntry struct {
	state    circuitState
	failures int
	openedAt time.Time
}

// CircuitBreakerStore はインメモリのサーキットブレーカーストア。
type CircuitBreakerStore struct {
	mu          sync.Mutex
	entries     map[string]*circuitEntry
	maxFailures int
	timeout     time.Duration // open → half-open に遷移するまでの待機時間
	now         func() time.Time
}

// CircuitBreakerStoreOption は CircuitBreakerStore の動作をカスタマイズするオプション関数。
type CircuitBreakerStoreOption func(*CircuitBreakerStore)

// WithCircuitBreakerClock はテスト用に時刻関数を差し替える。
func WithCircuitBreakerClock(fn func() time.Time) CircuitBreakerStoreOption {
	return func(c *CircuitBreakerStore) {
		c.now = fn
	}
}

// NewCircuitBreakerStore は新しい CircuitBreakerStore を生成する。
// maxFailures は open に遷移する失敗回数、timeout は open → half-open の待機時間。
func NewCircuitBreakerStore(maxFailures int, timeout time.Duration, opts ...CircuitBreakerStoreOption) *CircuitBreakerStore {
	c := &CircuitBreakerStore{
		entries:     make(map[string]*circuitEntry),
		maxFailures: maxFailures,
		timeout:     timeout,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// getOrCreate は upstream のエントリを取得し、存在しなければ作成する。
// 呼び出し元でロックを取得済みであること。
func (c *CircuitBreakerStore) getOrCreate(upstream string) *circuitEntry {
	e, ok := c.entries[upstream]
	if !ok {
		e = &circuitEntry{state: stateClosed}
		c.entries[upstream] = e
	}
	return e
}

// RecordSuccess は成功を記録し、状態を closed にリセットする。
func (c *CircuitBreakerStore) RecordSuccess(upstream string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.getOrCreate(upstream)
	e.failures = 0
	e.state = stateClosed
	return nil
}

// RecordFailure は失敗を記録する。
// maxFailures に達した場合は状態を open に遷移させる。
func (c *CircuitBreakerStore) RecordFailure(upstream string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.getOrCreate(upstream)
	e.failures++
	if e.failures >= c.maxFailures {
		e.state = stateOpen
		e.openedAt = c.now()
	}
	return nil
}

// Allow はリクエストの通過を許可するかを判定する。
// 戻り値は (許可フラグ, 現在状態文字列, エラー)。
func (c *CircuitBreakerStore) Allow(upstream string) (bool, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.getOrCreate(upstream)

	switch e.state {
	case stateClosed:
		return true, "closed", nil
	case stateOpen:
		if c.now().Sub(e.openedAt) >= c.timeout {
			e.state = stateHalfOpen
			return true, "half-open", nil
		}
		return false, "open", nil
	case stateHalfOpen:
		// half-open 中は 1 リクエストのみ通過済み — 追加は拒否
		return false, "half-open", nil
	}
	return true, "closed", nil
}

// State は指定 upstream のサーキットブレーカー状態を文字列で返す。
func (c *CircuitBreakerStore) State(upstream string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[upstream]
	if !ok {
		return "closed", nil
	}

	switch e.state {
	case stateClosed:
		return "closed", nil
	case stateOpen:
		// タイムアウト経過時は half-open を返す（読み取り時に状態遷移はしない）
		if c.now().Sub(e.openedAt) >= c.timeout {
			return "half-open", nil
		}
		return "open", nil
	case stateHalfOpen:
		return "half-open", nil
	default:
		return "closed", nil
	}
}
