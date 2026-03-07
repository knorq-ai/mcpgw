package proxy

import (
	"bufio"
	"io"
	"strings"
)

// SSEEvent は Server-Sent Events の1イベントを表す。
type SSEEvent struct {
	ID    string
	Event string
	Data  string
}

// SSEScanner は io.Reader から SSE イベントストリームを読み取る。
// 空行でイベントを区切り、`:` 先頭行はコメントとしてスキップする。
type SSEScanner struct {
	scanner *bufio.Scanner
	event   *SSEEvent
	err     error
}

// NewSSEScanner は io.Reader から SSE イベントを読み取る SSEScanner を生成する。
func NewSSEScanner(r io.Reader) *SSEScanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	return &SSEScanner{scanner: s}
}

// Scan は次のイベントを読み取る。イベントが存在する場合 true を返す。
func (s *SSEScanner) Scan() bool {
	var id, event string
	var dataLines []string
	hasFields := false

	for s.scanner.Scan() {
		line := s.scanner.Text()

		// 空行 → イベント区切り
		if line == "" {
			if hasFields {
				s.event = &SSEEvent{
					ID:    id,
					Event: event,
					Data:  strings.Join(dataLines, "\n"),
				}
				return true
			}
			continue
		}

		// コメント行
		if strings.HasPrefix(line, ":") {
			continue
		}

		// フィールドパース
		field, value := parseSSEField(line)
		switch field {
		case "data":
			dataLines = append(dataLines, value)
			hasFields = true
		case "event":
			event = value
			hasFields = true
		case "id":
			id = value
			hasFields = true
		}
	}

	s.err = s.scanner.Err()

	// ストリーム末尾で未送信のイベントがある場合
	if hasFields {
		s.event = &SSEEvent{
			ID:    id,
			Event: event,
			Data:  strings.Join(dataLines, "\n"),
		}
		return true
	}

	return false
}

// Event は最後に読み取ったイベントを返す。
func (s *SSEScanner) Event() *SSEEvent {
	return s.event
}

// Err はスキャン中に発生したエラーを返す。
func (s *SSEScanner) Err() error {
	return s.err
}

// parseSSEField は SSE 行をフィールド名と値に分割する。
// "field: value" → ("field", "value")
// "field:value"  → ("field", "value")
// "field"        → ("field", "")
func parseSSEField(line string) (field, value string) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return line, ""
	}
	field = line[:idx]
	value = line[idx+1:]
	// 先頭の1スペースのみ除去（仕様準拠）
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return field, value
}

// FormatSSEEvent は SSEEvent を SSE フォーマットのバイト列に変換する。
func FormatSSEEvent(ev *SSEEvent) []byte {
	var b strings.Builder
	if ev.Event != "" {
		b.WriteString("event: ")
		b.WriteString(ev.Event)
		b.WriteByte('\n')
	}
	if ev.ID != "" {
		b.WriteString("id: ")
		b.WriteString(ev.ID)
		b.WriteByte('\n')
	}
	for _, line := range strings.Split(ev.Data, "\n") {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return []byte(b.String())
}
