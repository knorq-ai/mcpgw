package proxy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSEScannerSingleEvent(t *testing.T) {
	input := "data: hello\n\n"
	s := NewSSEScanner(strings.NewReader(input))

	require.True(t, s.Scan())
	ev := s.Event()
	assert.Equal(t, "hello", ev.Data)
	assert.Equal(t, "", ev.Event)
	assert.Equal(t, "", ev.ID)

	assert.False(t, s.Scan())
	assert.NoError(t, s.Err())
}

func TestSSEScannerMultipleEvents(t *testing.T) {
	input := "data: one\n\ndata: two\n\ndata: three\n\n"
	s := NewSSEScanner(strings.NewReader(input))

	var events []*SSEEvent
	for s.Scan() {
		ev := s.Event()
		events = append(events, &SSEEvent{
			ID:    ev.ID,
			Event: ev.Event,
			Data:  ev.Data,
		})
	}
	require.NoError(t, s.Err())
	require.Len(t, events, 3)
	assert.Equal(t, "one", events[0].Data)
	assert.Equal(t, "two", events[1].Data)
	assert.Equal(t, "three", events[2].Data)
}

func TestSSEScannerMultiLineData(t *testing.T) {
	input := "data: line1\ndata: line2\ndata: line3\n\n"
	s := NewSSEScanner(strings.NewReader(input))

	require.True(t, s.Scan())
	ev := s.Event()
	assert.Equal(t, "line1\nline2\nline3", ev.Data)
}

func TestSSEScannerCommentLines(t *testing.T) {
	input := ": this is a comment\ndata: actual data\n: another comment\n\n"
	s := NewSSEScanner(strings.NewReader(input))

	require.True(t, s.Scan())
	ev := s.Event()
	assert.Equal(t, "actual data", ev.Data)

	assert.False(t, s.Scan())
}

func TestSSEScannerEmptyStream(t *testing.T) {
	s := NewSSEScanner(strings.NewReader(""))
	assert.False(t, s.Scan())
	assert.NoError(t, s.Err())
}

func TestSSEScannerPartialEvent(t *testing.T) {
	// ストリーム末尾に空行がない場合 → イベントを返す
	input := "data: partial"
	s := NewSSEScanner(strings.NewReader(input))

	require.True(t, s.Scan())
	ev := s.Event()
	assert.Equal(t, "partial", ev.Data)

	assert.False(t, s.Scan())
}

func TestSSEScannerAllFields(t *testing.T) {
	input := "event: message\nid: 42\ndata: payload\n\n"
	s := NewSSEScanner(strings.NewReader(input))

	require.True(t, s.Scan())
	ev := s.Event()
	assert.Equal(t, "message", ev.Event)
	assert.Equal(t, "42", ev.ID)
	assert.Equal(t, "payload", ev.Data)
}

func TestSSEScannerNoSpaceAfterColon(t *testing.T) {
	input := "data:no-space\n\n"
	s := NewSSEScanner(strings.NewReader(input))

	require.True(t, s.Scan())
	assert.Equal(t, "no-space", s.Event().Data)
}

func TestSSEScannerMultipleEmptyLines(t *testing.T) {
	// 連続する空行はイベント区切りとして扱い、空イベントは生成しない
	input := "\n\n\ndata: after-blanks\n\n"
	s := NewSSEScanner(strings.NewReader(input))

	require.True(t, s.Scan())
	assert.Equal(t, "after-blanks", s.Event().Data)

	assert.False(t, s.Scan())
}

func TestFormatSSEEvent(t *testing.T) {
	tests := []struct {
		name string
		ev   *SSEEvent
		want string
	}{
		{
			name: "data only",
			ev:   &SSEEvent{Data: "hello"},
			want: "data: hello\n\n",
		},
		{
			name: "all fields",
			ev:   &SSEEvent{Event: "message", ID: "1", Data: "payload"},
			want: "event: message\nid: 1\ndata: payload\n\n",
		},
		{
			name: "multi-line data",
			ev:   &SSEEvent{Data: "line1\nline2"},
			want: "data: line1\ndata: line2\n\n",
		},
		{
			name: "empty data",
			ev:   &SSEEvent{Data: ""},
			want: "data: \n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(FormatSSEEvent(tt.ev))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSSEScannerRoundTrip(t *testing.T) {
	// FormatSSEEvent で生成したバイト列を SSEScanner で読み取り、元のイベントと一致することを確認
	original := &SSEEvent{Event: "message", ID: "99", Data: "line1\nline2"}
	formatted := FormatSSEEvent(original)

	s := NewSSEScanner(strings.NewReader(string(formatted)))
	require.True(t, s.Scan())
	ev := s.Event()
	assert.Equal(t, original.Event, ev.Event)
	assert.Equal(t, original.ID, ev.ID)
	assert.Equal(t, original.Data, ev.Data)
}
