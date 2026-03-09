// Package state はステートストアの抽象インターフェースを定義する。
// セッション管理・レート制限・サーキットブレーカーの状態を
// バックエンド非依存で扱えるようにする。
package state

import "time"

// SessionStore はセッションの追跡・削除・カウントを行うストア。
// 各実装はスレッドセーフであること。
type SessionStore interface {
	// Track はセッションを追跡対象に追加する。
	// 既に存在する場合は最終アクセス時刻を更新する。
	Track(sid string) error

	// Remove はセッションを追跡対象から削除する。
	// 存在しないセッションの削除はエラーにならない。
	Remove(sid string) error

	// Count は現在追跡中のセッション数を返す。
	Count() (int, error)

	// Touch はセッションの最終アクセス時刻を更新する。
	// 存在しないセッションに対しては何もしない。
	Touch(sid string) error

	// Cleanup は ttl を超過したセッションを削除し、削除件数を返す。
	Cleanup(ttl time.Duration) (int, error)
}

// RateLimitStore はキー単位のレート制限を行うストア。
// トークンバケットアルゴリズムに基づく。
type RateLimitStore interface {
	// Allow はキーに対するリクエストを許可するかを判定する。
	// rate はトークン補充レート (tokens/sec)、burst は最大トークン数。
	// 許可された場合はトークンを 1 消費する。
	Allow(key string, rate float64, burst int) (bool, error)
}

// CircuitBreakerStore は upstream 単位のサーキットブレーカー状態を管理するストア。
type CircuitBreakerStore interface {
	// RecordSuccess は成功を記録し、状態を closed にリセットする。
	RecordSuccess(upstream string) error

	// RecordFailure は失敗を記録する。
	// maxFailures に達した場合は状態を open に遷移させる。
	RecordFailure(upstream string) error

	// Allow はリクエストの通過を許可するかを判定する。
	// 戻り値は (許可フラグ, 現在状態文字列, エラー)。
	// 状態文字列は "closed", "open", "half-open" のいずれか。
	Allow(upstream string) (allowed bool, state string, err error)

	// State は指定 upstream のサーキットブレーカー状態を文字列で返す。
	// 未登録の upstream は "closed" を返す。
	State(upstream string) (string, error)
}
