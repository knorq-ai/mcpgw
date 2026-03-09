package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhookAlerterSend(t *testing.T) {
	var mu sync.Mutex
	var received []Payload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		mu.Lock()
		received = append(received, p)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	alerter := NewWebhookAlerter(srv.URL, 1*time.Second)
	defer alerter.Close()

	alerter.Alert(Payload{
		RuleName: "block-exec",
		Method:   "tools/call",
		ToolName: "exec_cmd",
		Reason:   "denied by policy",
		Subject:  "user-a",
	})

	// 非同期送信を待機
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	require.Len(t, received, 1)
	assert.Equal(t, "block-exec", received[0].RuleName)
	assert.Equal(t, "exec_cmd", received[0].ToolName)
	assert.NotEmpty(t, received[0].Timestamp)
	mu.Unlock()
}

func TestWebhookAlerterDedup(t *testing.T) {
	var mu sync.Mutex
	var count int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	alerter := NewWebhookAlerter(srv.URL, 5*time.Second)
	defer alerter.Close()

	p := Payload{
		RuleName: "block-exec",
		ToolName: "exec_cmd",
		Subject:  "user-a",
	}

	// 同じアラートを3回送信
	alerter.Alert(p)
	alerter.Alert(p)
	alerter.Alert(p)

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	// dedup window 内なので1回のみ送信される
	assert.Equal(t, 1, count)
	mu.Unlock()
}

func TestWebhookAlerterDedupDifferentKeys(t *testing.T) {
	var mu sync.Mutex
	var count int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	alerter := NewWebhookAlerter(srv.URL, 5*time.Second)
	defer alerter.Close()

	// 異なるキーのアラート → 両方送信
	alerter.Alert(Payload{RuleName: "rule-a", ToolName: "tool-a"})
	alerter.Alert(Payload{RuleName: "rule-b", ToolName: "tool-b"})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	assert.Equal(t, 2, count)
	mu.Unlock()
}

func TestWebhookAlerterServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	alerter := NewWebhookAlerter(srv.URL, 1*time.Second)
	defer alerter.Close()

	// サーバーエラーでもパニックしない
	alerter.Alert(Payload{RuleName: "rule", ToolName: "tool"})
	time.Sleep(100 * time.Millisecond)
}
