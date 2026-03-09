package alert

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Payload は webhook に送信するアラートペイロード。
type Payload struct {
	Timestamp string `json:"timestamp"`
	RuleName  string `json:"rule_name"`
	Method    string `json:"method"`
	ToolName  string `json:"tool_name,omitempty"`
	Reason    string `json:"reason"`
	Subject   string `json:"subject,omitempty"`
}

// WebhookAlerter はブロック時に HTTP POST webhook で即時通知する。
// dedup window 内の同一ルールのアラートは重複排除する。
type WebhookAlerter struct {
	url         string
	client      *http.Client
	dedupWindow time.Duration
	mu          sync.Mutex
	seen        map[string]time.Time // key → 最後に送信した時刻
	wg          sync.WaitGroup       // in-flight send goroutine の追跡
	stopCh      chan struct{}
	stopped     chan struct{}
}

// NewWebhookAlerter は WebhookAlerter を生成する。
func NewWebhookAlerter(url string, dedupWindow time.Duration) *WebhookAlerter {
	if dedupWindow <= 0 {
		dedupWindow = 5 * time.Minute
	}
	w := &WebhookAlerter{
		url:         url,
		client:      &http.Client{Timeout: 5 * time.Second},
		dedupWindow: dedupWindow,
		seen:        make(map[string]time.Time),
		stopCh:      make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	go w.sweepLoop()
	return w
}

// Alert はアラートを送信する。dedup window 内の同一キーは抑制する。
func (w *WebhookAlerter) Alert(p Payload) {
	key := p.RuleName + ":" + p.ToolName + ":" + p.Subject
	w.mu.Lock()
	if last, ok := w.seen[key]; ok && time.Since(last) < w.dedupWindow {
		w.mu.Unlock()
		return // 重複排除
	}
	w.seen[key] = time.Now()
	w.mu.Unlock()

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.send(p)
	}()
}

func (w *WebhookAlerter) send(p Payload) {
	if p.Timestamp == "" {
		p.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(p)
	if err != nil {
		slog.Error("webhook marshal error", "error", err)
		return
	}

	resp, err := w.client.Post(w.url, "application/json", bytes.NewReader(body))
	if err != nil {
		slog.Warn("webhook send failed", "url", w.url, "error", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Warn("webhook returned error", "url", w.url, "status", resp.StatusCode)
	}
}

func (w *WebhookAlerter) sweepLoop() {
	defer close(w.stopped)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.sweep()
		}
	}
}

func (w *WebhookAlerter) sweep() {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := time.Now().Add(-w.dedupWindow * 2)
	for k, t := range w.seen {
		if t.Before(cutoff) {
			delete(w.seen, k)
		}
	}
}

// Close は sweep goroutine を停止し、in-flight の送信を待機する。
func (w *WebhookAlerter) Close() {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
	<-w.stopped
	w.wg.Wait()
}
