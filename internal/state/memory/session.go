package memory

import (
	"sync"
	"time"
)

// SessionStore はインメモリのセッションストア。
// sync.Mutex でスレッドセーフを保証する。
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time // sid → 最終アクセス時刻
	now      func() time.Time
}

// SessionStoreOption は SessionStore の動作をカスタマイズするオプション関数。
type SessionStoreOption func(*SessionStore)

// WithSessionClock はテスト用に時刻関数を差し替える。
func WithSessionClock(fn func() time.Time) SessionStoreOption {
	return func(s *SessionStore) {
		s.now = fn
	}
}

// NewSessionStore は新しい SessionStore を生成する。
func NewSessionStore(opts ...SessionStoreOption) *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]time.Time),
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Track はセッションを追跡対象に追加する。
// 既に存在する場合は最終アクセス時刻を更新する。
func (s *SessionStore) Track(sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sid] = s.now()
	return nil
}

// Remove はセッションを追跡対象から削除する。
func (s *SessionStore) Remove(sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sid)
	return nil
}

// Count は現在追跡中のセッション数を返す。
func (s *SessionStore) Count() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions), nil
}

// Touch はセッションの最終アクセス時刻を更新する。
// 存在しないセッションに対しては何もしない。
func (s *SessionStore) Touch(sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sid]; ok {
		s.sessions[sid] = s.now()
	}
	return nil
}

// Cleanup は ttl を超過したセッションを削除し、削除件数を返す。
func (s *SessionStore) Cleanup(ttl time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-ttl)
	removed := 0
	for sid, lastAccess := range s.sessions {
		if lastAccess.Before(cutoff) {
			delete(s.sessions, sid)
			removed++
		}
	}
	return removed, nil
}
