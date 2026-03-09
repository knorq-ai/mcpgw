package memory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

func TestSessionStore_TrackAndCount(t *testing.T) {
	s := NewSessionStore()

	require.NoError(t, s.Track("s1"))
	require.NoError(t, s.Track("s2"))

	n, err := s.Count()
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestSessionStore_TrackDuplicate(t *testing.T) {
	now := time.Now()
	s := NewSessionStore(WithSessionClock(func() time.Time { return now }))

	require.NoError(t, s.Track("s1"))
	require.NoError(t, s.Track("s1")) // 重複登録

	n, err := s.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, n, "重複 Track でカウントが増加してはならない")
}

func TestSessionStore_Remove(t *testing.T) {
	s := NewSessionStore()

	require.NoError(t, s.Track("s1"))
	require.NoError(t, s.Remove("s1"))

	n, err := s.Count()
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestSessionStore_RemoveNonExistent(t *testing.T) {
	s := NewSessionStore()
	// 存在しないセッションの削除はエラーにならない
	require.NoError(t, s.Remove("nonexistent"))
}

func TestSessionStore_Touch(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	s := NewSessionStore(WithSessionClock(nowFn))

	require.NoError(t, s.Track("s1"))

	// 時刻を進めて Touch
	now = now.Add(10 * time.Minute)
	require.NoError(t, s.Touch("s1"))

	// TTL=15分 で Cleanup — Touch 後なのでまだ生存
	removed, err := s.Cleanup(15 * time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 0, removed)

	n, err := s.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestSessionStore_TouchNonExistent(t *testing.T) {
	s := NewSessionStore()
	// 存在しないセッションへの Touch はエラーにならない
	require.NoError(t, s.Touch("nonexistent"))
}

func TestSessionStore_Cleanup(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	s := NewSessionStore(WithSessionClock(nowFn))

	require.NoError(t, s.Track("old"))
	require.NoError(t, s.Track("new"))

	// 30 分経過
	now = now.Add(30 * time.Minute)

	// "new" だけ Touch
	require.NoError(t, s.Touch("new"))

	// TTL=20分 で Cleanup → "old" のみ削除
	removed, err := s.Cleanup(20 * time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	n, err := s.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestSessionStore_CleanupAll(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	s := NewSessionStore(WithSessionClock(nowFn))

	require.NoError(t, s.Track("s1"))
	require.NoError(t, s.Track("s2"))

	// 1 時間経過
	now = now.Add(1 * time.Hour)

	removed, err := s.Cleanup(30 * time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 2, removed)

	n, err := s.Count()
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// ---------------------------------------------------------------------------
// RateLimitStore
// ---------------------------------------------------------------------------

func TestRateLimitStore_AllowBurst(t *testing.T) {
	now := time.Now()
	r := NewRateLimitStore(WithRateLimitClock(func() time.Time { return now }))

	// burst=3: 3 回は通過
	for i := 0; i < 3; i++ {
		ok, err := r.Allow("key1", 1.0, 3)
		require.NoError(t, err)
		assert.True(t, ok, "burst 範囲内 (%d)", i)
	}

	// 4 回目はブロック
	ok, err := r.Allow("key1", 1.0, 3)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRateLimitStore_AllowRefill(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	r := NewRateLimitStore(WithRateLimitClock(nowFn))

	// burst=1, rate=1.0 tokens/sec
	ok, err := r.Allow("k", 1.0, 1)
	require.NoError(t, err)
	assert.True(t, ok)

	// トークン枯渇
	ok, err = r.Allow("k", 1.0, 1)
	require.NoError(t, err)
	assert.False(t, ok)

	// 1 秒経過 → トークン補充
	now = now.Add(1 * time.Second)
	ok, err = r.Allow("k", 1.0, 1)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestRateLimitStore_KeyIsolation(t *testing.T) {
	now := time.Now()
	r := NewRateLimitStore(WithRateLimitClock(func() time.Time { return now }))

	// key-a: burst=1
	ok, err := r.Allow("key-a", 1.0, 1)
	require.NoError(t, err)
	assert.True(t, ok)

	// key-a 枯渇
	ok, err = r.Allow("key-a", 1.0, 1)
	require.NoError(t, err)
	assert.False(t, ok)

	// key-b は別バケット — 通過する
	ok, err = r.Allow("key-b", 1.0, 1)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestRateLimitStore_Cleanup(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	r := NewRateLimitStore(WithRateLimitClock(nowFn))

	// バケットを作成
	_, _ = r.Allow("old-key", 1.0, 1)
	_, _ = r.Allow("new-key", 1.0, 1)

	// 10 分経過
	now = now.Add(10 * time.Minute)

	// new-key だけアクセス
	_, _ = r.Allow("new-key", 1.0, 1)

	// maxAge=5分 で Cleanup → old-key のみ削除
	removed := r.Cleanup(5 * time.Minute)
	assert.Equal(t, 1, removed)

	// new-key はまだ存在するはず（Allow できる ≒ バケットが残っている）
	// old-key は削除されたので新規バケットが作られ burst 分通過する
	ok, err := r.Allow("old-key", 1.0, 1)
	require.NoError(t, err)
	assert.True(t, ok, "削除後は新規バケットとして burst 分通過する")
}

func TestRateLimitStore_BurstCap(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	r := NewRateLimitStore(WithRateLimitClock(nowFn))

	// burst=2, rate=1.0
	ok, _ := r.Allow("k", 1.0, 2)
	assert.True(t, ok)
	ok, _ = r.Allow("k", 1.0, 2)
	assert.True(t, ok)

	// 長時間経過してもトークンは burst を超えない
	now = now.Add(10 * time.Second)
	// 1 回消費
	ok, _ = r.Allow("k", 1.0, 2)
	assert.True(t, ok)
	ok, _ = r.Allow("k", 1.0, 2)
	assert.True(t, ok)
	// burst=2 なので 3 回目はブロック
	ok, _ = r.Allow("k", 1.0, 2)
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// CircuitBreakerStore
// ---------------------------------------------------------------------------

func TestCircuitBreakerStore_InitialClosed(t *testing.T) {
	c := NewCircuitBreakerStore(3, 10*time.Second)

	st, err := c.State("upstream-a")
	require.NoError(t, err)
	assert.Equal(t, "closed", st)

	allowed, st, err := c.Allow("upstream-a")
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, "closed", st)
}

func TestCircuitBreakerStore_OpenAfterMaxFailures(t *testing.T) {
	now := time.Now()
	c := NewCircuitBreakerStore(3, 10*time.Second,
		WithCircuitBreakerClock(func() time.Time { return now }))

	// 3 回失敗 → open
	for i := 0; i < 3; i++ {
		require.NoError(t, c.RecordFailure("up"))
	}

	allowed, st, err := c.Allow("up")
	require.NoError(t, err)
	assert.False(t, allowed)
	assert.Equal(t, "open", st)
}

func TestCircuitBreakerStore_HalfOpenAfterTimeout(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	c := NewCircuitBreakerStore(2, 5*time.Second, WithCircuitBreakerClock(nowFn))

	// 2 回失敗 → open
	require.NoError(t, c.RecordFailure("up"))
	require.NoError(t, c.RecordFailure("up"))

	// open 確認
	allowed, st, _ := c.Allow("up")
	assert.False(t, allowed)
	assert.Equal(t, "open", st)

	// タイムアウト経過 → half-open
	now = now.Add(5 * time.Second)
	allowed, st, _ = c.Allow("up")
	assert.True(t, allowed, "half-open では 1 リクエスト通過")
	assert.Equal(t, "half-open", st)

	// half-open 中の追加リクエストは拒否
	allowed, st, _ = c.Allow("up")
	assert.False(t, allowed)
	assert.Equal(t, "half-open", st)
}

func TestCircuitBreakerStore_SuccessResetsToClosed(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	c := NewCircuitBreakerStore(2, 5*time.Second, WithCircuitBreakerClock(nowFn))

	// open にする
	require.NoError(t, c.RecordFailure("up"))
	require.NoError(t, c.RecordFailure("up"))

	// タイムアウト経過 → half-open
	now = now.Add(5 * time.Second)
	allowed, _, _ := c.Allow("up")
	assert.True(t, allowed)

	// 成功 → closed にリセット
	require.NoError(t, c.RecordSuccess("up"))

	allowed, st, _ := c.Allow("up")
	assert.True(t, allowed)
	assert.Equal(t, "closed", st)
}

func TestCircuitBreakerStore_FailureInHalfOpenReOpens(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	c := NewCircuitBreakerStore(1, 5*time.Second, WithCircuitBreakerClock(nowFn))

	// 1 回失敗 → open
	require.NoError(t, c.RecordFailure("up"))
	allowed, st, _ := c.Allow("up")
	assert.False(t, allowed)
	assert.Equal(t, "open", st)

	// タイムアウト経過 → half-open
	now = now.Add(5 * time.Second)
	allowed, st, _ = c.Allow("up")
	assert.True(t, allowed)
	assert.Equal(t, "half-open", st)

	// half-open で失敗 → 再度 open
	require.NoError(t, c.RecordFailure("up"))
	allowed, st, _ = c.Allow("up")
	assert.False(t, allowed)
	assert.Equal(t, "open", st)
}

func TestCircuitBreakerStore_UpstreamIsolation(t *testing.T) {
	c := NewCircuitBreakerStore(1, 10*time.Second)

	// upstream-a を open にする
	require.NoError(t, c.RecordFailure("upstream-a"))
	allowed, _, _ := c.Allow("upstream-a")
	assert.False(t, allowed)

	// upstream-b は独立 — closed のまま
	allowed, st, _ := c.Allow("upstream-b")
	assert.True(t, allowed)
	assert.Equal(t, "closed", st)
}

func TestCircuitBreakerStore_StateReflectsTimeout(t *testing.T) {
	now := time.Now()
	nowFn := func() time.Time { return now }
	c := NewCircuitBreakerStore(1, 5*time.Second, WithCircuitBreakerClock(nowFn))

	require.NoError(t, c.RecordFailure("up"))
	st, _ := c.State("up")
	assert.Equal(t, "open", st)

	// タイムアウト経過 → State() は half-open を返す
	now = now.Add(5 * time.Second)
	st, _ = c.State("up")
	assert.Equal(t, "half-open", st)
}

func TestCircuitBreakerStore_PartialFailures(t *testing.T) {
	c := NewCircuitBreakerStore(3, 10*time.Second)

	// 2 回失敗（閾値未満）
	require.NoError(t, c.RecordFailure("up"))
	require.NoError(t, c.RecordFailure("up"))

	// まだ closed
	allowed, st, _ := c.Allow("up")
	assert.True(t, allowed)
	assert.Equal(t, "closed", st)

	// 成功でリセット
	require.NoError(t, c.RecordSuccess("up"))

	// 再度 2 回失敗 → まだ closed
	require.NoError(t, c.RecordFailure("up"))
	require.NoError(t, c.RecordFailure("up"))
	allowed, st, _ = c.Allow("up")
	assert.True(t, allowed)
	assert.Equal(t, "closed", st)
}

// ---------------------------------------------------------------------------
// インターフェース準拠のコンパイル時チェック
// ---------------------------------------------------------------------------

// state パッケージのインターフェースをインポートしてコンパイル時に型チェックする。
// テストファイル内でのみ使用。
func TestInterfaceCompliance(t *testing.T) {
	// コンパイル時の型チェック（実行時には何もしない）
	// state パッケージのインターフェースを満たすことを保証する。
	t.Run("SessionStore", func(t *testing.T) {
		var _ interface {
			Track(string) error
			Remove(string) error
			Count() (int, error)
			Touch(string) error
			Cleanup(time.Duration) (int, error)
		} = NewSessionStore()
	})
	t.Run("RateLimitStore", func(t *testing.T) {
		var _ interface {
			Allow(string, float64, int) (bool, error)
		} = NewRateLimitStore()
	})
	t.Run("CircuitBreakerStore", func(t *testing.T) {
		var _ interface {
			RecordSuccess(string) error
			RecordFailure(string) error
			Allow(string) (bool, string, error)
			State(string) (string, error)
		} = NewCircuitBreakerStore(3, 10*time.Second)
	})
}
