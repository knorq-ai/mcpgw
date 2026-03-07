package jsonrpc

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageKind(t *testing.T) {
	tests := []struct {
		name string
		json string
		kind Kind
	}{
		{
			name: "request",
			json: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
			kind: KindRequest,
		},
		{
			name: "response with result",
			json: `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`,
			kind: KindResponse,
		},
		{
			name: "response with error",
			json: `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}`,
			kind: KindResponse,
		},
		{
			name: "notification",
			json: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			kind: KindNotification,
		},
		{
			name: "string id",
			json: `{"jsonrpc":"2.0","id":"abc","method":"tools/call"}`,
			kind: KindRequest,
		},
		{
			name: "null id treated as no id",
			json: `{"jsonrpc":"2.0","id":null,"method":"notifications/initialized"}`,
			kind: KindNotification,
		},
		{
			name: "empty message",
			json: `{"jsonrpc":"2.0"}`,
			kind: KindUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg Message
			require.NoError(t, json.Unmarshal([]byte(tt.json), &msg))
			assert.Equal(t, tt.kind, msg.Kind())
		})
	}
}

func TestMessageHelpers(t *testing.T) {
	req := Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/list"}
	assert.True(t, req.IsRequest())
	assert.False(t, req.IsResponse())
	assert.False(t, req.IsNotification())

	resp := Message{JSONRPC: "2.0", ID: json.RawMessage(`1`), Result: json.RawMessage(`{}`)}
	assert.False(t, resp.IsRequest())
	assert.True(t, resp.IsResponse())

	notif := Message{JSONRPC: "2.0", Method: "notifications/initialized"}
	assert.True(t, notif.IsNotification())
}

func TestScannerBasic(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}, "\n") + "\n"

	scanner := NewScanner(strings.NewReader(input))
	var messages []*Message
	for scanner.Scan() {
		msg := scanner.Message()
		require.NotNil(t, msg)
		messages = append(messages, msg)
	}
	require.NoError(t, scanner.Err())
	require.Len(t, messages, 3)
	assert.Equal(t, KindRequest, messages[0].Kind())
	assert.Equal(t, KindResponse, messages[1].Kind())
	assert.Equal(t, KindNotification, messages[2].Kind())
}

func TestScannerSkipsEmptyLines(t *testing.T) {
	input := "\n\n" + `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n\n"
	scanner := NewScanner(strings.NewReader(input))
	count := 0
	for scanner.Scan() {
		count++
		assert.NotNil(t, scanner.Message())
	}
	assert.Equal(t, 1, count)
}

func TestScannerInvalidJSON(t *testing.T) {
	input := "not valid json\n"
	scanner := NewScanner(strings.NewReader(input))
	require.True(t, scanner.Scan())
	// fail-open: パース失敗でも生バイトを返す
	assert.Nil(t, scanner.Message())
	assert.Equal(t, []byte("not valid json"), scanner.Raw())
}

func TestScannerPreservesRawBytes(t *testing.T) {
	// スペースや順序が保持されることを確認
	original := `{"jsonrpc" : "2.0", "id":  1, "method": "test"}`
	scanner := NewScanner(strings.NewReader(original + "\n"))
	require.True(t, scanner.Scan())
	assert.Equal(t, []byte(original), scanner.Raw())
}

func TestEncode(t *testing.T) {
	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/list",
	}
	var buf bytes.Buffer
	require.NoError(t, Encode(&buf, msg))
	assert.Contains(t, buf.String(), `"jsonrpc":"2.0"`)
	assert.True(t, strings.HasSuffix(buf.String(), "\n"))
}

func TestEncodeRaw(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`)
	var buf bytes.Buffer
	require.NoError(t, EncodeRaw(&buf, raw))
	assert.Equal(t, string(raw)+"\n", buf.String())
}
