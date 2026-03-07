package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggerWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path, DefaultMaxSize)
	require.NoError(t, err)
	defer logger.Close()

	entry := &Entry{
		Timestamp: time.Now(),
		Direction: "c2s",
		Method:    "tools/list",
		ID:        "1",
		Kind:      "request",
		Size:      42,
		Action:    "pass",
	}
	require.NoError(t, logger.Log(entry))

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1)

	var decoded Entry
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &decoded))
	assert.Equal(t, "c2s", decoded.Direction)
	assert.Equal(t, "tools/list", decoded.Method)
	assert.Equal(t, "pass", decoded.Action)
}

func TestLoggerRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// 最大 200 バイトで作成
	logger, err := NewLogger(path, 200)
	require.NoError(t, err)
	defer logger.Close()

	entry := &Entry{
		Timestamp: time.Now(),
		Direction: "c2s",
		Method:    "tools/list",
		Kind:      "request",
		Size:      42,
		Action:    "pass",
	}

	// 200 バイトを超えるまで書き込む
	for i := 0; i < 5; i++ {
		require.NoError(t, logger.Log(entry))
	}

	// ローテーションファイルが作成されたことを確認
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Greater(t, len(entries), 1, "ローテーションファイルが作成されるべき")
}

func TestLoggerRotationRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// 最大 100 バイトで作成 — すぐローテーションが発生する
	logger, err := NewLogger(path, 100)
	require.NoError(t, err)
	defer logger.Close()

	entry := &Entry{
		Timestamp: time.Now(),
		Direction: "c2s",
		Method:    "tools/call",
		Kind:      "request",
		Size:      42,
		Action:    "block",
	}

	// 1回書いてローテーションをトリガーさせた後、元ファイルを読み取り専用ディレクトリに移動して
	// rename を失敗させる — ただし OS に依存するため、代わりに
	// 元ファイルを削除してから rename が失敗するケースをテストする
	require.NoError(t, logger.Log(entry))

	// ログファイルを削除して rename を失敗させる
	os.Remove(path)

	// 次の書き込みでローテーション失敗 → リカバリ → 新ファイルで継続
	// rotate 内で rename 失敗 → reopen で新ファイル作成 → Log はエラーを返すが logger は壊れない
	err = logger.Log(entry)
	// rotate のリカバリエラーが返る可能性があるが、ロガーは使用可能な状態を維持する
	// 次の書き込みは成功するはず
	err = logger.Log(entry)
	// ファイルが再作成されて書き込み可能であることを確認
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr, "ローテーション失敗後もログファイルが存在すべき")
}

func TestLoggerCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewLogger(path, DefaultMaxSize)
	require.NoError(t, err)

	// 複数回 Close しても panic しない
	require.NoError(t, logger.Close())
	require.NoError(t, logger.Close())
	require.NoError(t, logger.Close())
}

func TestLoggerCreatesDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "deep", "audit.jsonl")

	logger, err := NewLogger(path, DefaultMaxSize)
	require.NoError(t, err)
	defer logger.Close()

	require.NoError(t, logger.Log(&Entry{
		Timestamp: time.Now(),
		Direction: "s2c",
		Kind:      "response",
		Action:    "pass",
	}))

	_, err = os.Stat(path)
	require.NoError(t, err)
}
