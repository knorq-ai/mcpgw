package memory

import (
	"sync"
	"time"
)

// RateLimitStore はインメモリのトークンバケットベースレート制限ストア。
type RateLimitStore struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time
}

// RateLimitStoreOption は RateLimitStore の動作をカスタマイズするオプション関数。
type RateLimitStoreOption func(*RateLimitStore)

// WithRateLimitClock はテスト用に時刻関数を差し替える。
func WithRateLimitClock(fn func() time.Time) RateLimitStoreOption {
	return func(r *RateLimitStore) {
		r.now = fn
	}
}

// NewRateLimitStore は新しい RateLimitStore を生成する。
func NewRateLimitStore(opts ...RateLimitStoreOption) *RateLimitStore {
	r := &RateLimitStore{
		buckets: make(map[string]*tokenBucket),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Allow はキーに対するリクエストを許可するかを判定する。
// rate はトークン補充レート (tokens/sec)、burst は最大トークン数。
// 許可された場合はトークンを 1 消費する。
func (r *RateLimitStore) Allow(key string, rate float64, burst int) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	b, ok := r.buckets[key]
	if !ok {
		b = &tokenBucket{
			tokens:   float64(burst),
			lastTime: now,
		}
		r.buckets[key] = b
	}

	// トークンを補充
	elapsed := now.Sub(b.lastTime).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.tokens += elapsed * rate
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.lastTime = now

	// トークン消費
	if b.tokens >= 1 {
		b.tokens--
		return true, nil
	}
	return false, nil
}

// Cleanup は lastTime が cutoff より古いバケットを削除する。
// 定期的に呼び出してメモリリークを防止する。
func (r *RateLimitStore) Cleanup(maxAge time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-maxAge)
	removed := 0
	for key, b := range r.buckets {
		if b.lastTime.Before(cutoff) {
			delete(r.buckets, key)
			removed++
		}
	}
	return removed
}
