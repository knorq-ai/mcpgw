package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultMaxSize はログファイルの最大サイズ（10MB）。
	DefaultMaxSize int64 = 10 * 1024 * 1024
)

// Logger は JSONL 形式で監査ログを書き出す。
// ファイルサイズが MaxSize を超えるとローテーションする。
type Logger struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	file    *os.File
	size    int64
}

// NewLogger は指定パスに JSONL ログを書き出す Logger を生成する。
// ディレクトリが存在しない場合は作成する。
func NewLogger(path string, maxSize int64) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: stat %s: %w", path, err)
	}

	return &Logger{
		path:    path,
		maxSize: maxSize,
		file:    f,
		size:    info.Size(),
	}, nil
}

// Log はエントリを JSONL 行として書き込む。
func (l *Logger) Log(entry *Entry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.size+int64(len(data)) > l.maxSize {
		if err := l.rotate(); err != nil {
			return fmt.Errorf("audit: rotate: %w", err)
		}
	}

	n, err := l.file.Write(data)
	l.size += int64(n)
	if err != nil {
		return err
	}

	// block エントリはフォレンジック上重要なため即座にディスクに書き出す
	if entry.Action == "block" {
		if syncErr := l.file.Sync(); syncErr != nil {
			return fmt.Errorf("audit: sync: %w", syncErr)
		}
	}
	return nil
}

// Close はログファイルを閉じる。冪等 — 複数回呼んでも安全。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// rotate はファイルをタイムスタンプ付きにリネームし、新しいファイルを開く。
// リネーム失敗時はファイルを再オープンしてロガーを回復する。
func (l *Logger) rotate() error {
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}

	ts := time.Now().Format("20060102-150405.000000000")
	ext := filepath.Ext(l.path)
	base := l.path[:len(l.path)-len(ext)]
	rotated := fmt.Sprintf("%s-%s%s", base, ts, ext)

	if err := os.Rename(l.path, rotated); err != nil {
		// リネーム失敗 — 元のパスでファイルを再オープンしてリカバリ
		f, openErr := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if openErr != nil {
			return fmt.Errorf("rotate rename failed: %w; reopen also failed: %v", err, openErr)
		}
		l.file = f
		// size はリセットしない — 既存ファイルに追記し続ける
		return fmt.Errorf("rotate rename failed (recovered): %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.file = f
	l.size = 0
	return nil
}
