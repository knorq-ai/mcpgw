package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// RequestsTotal は処理済みリクエストの総数。
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "mcpgw",
			Name:      "requests_total",
			Help:      "処理済みリクエスト数",
		},
		[]string{"method", "action"},
	)

	// RequestDuration はリクエスト処理時間のヒストグラム。
	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "mcpgw",
			Name:      "request_duration_seconds",
			Help:      "リクエスト処理時間（秒）",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	// ActiveSessions は現在アクティブなセッション数。
	ActiveSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "mcpgw",
			Name:      "active_sessions",
			Help:      "アクティブセッション数",
		},
	)

	// UpstreamErrors は upstream 通信エラーの総数。
	UpstreamErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "mcpgw",
			Name:      "upstream_errors_total",
			Help:      "Upstream 通信エラー数",
		},
	)

	// CircuitBreakerTrips はサーキットブレーカーが open 状態でリクエストを拒否した回数。
	CircuitBreakerTrips = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "mcpgw",
			Name:      "circuit_breaker_trips_total",
			Help:      "サーキットブレーカーによるリクエスト拒否数",
		},
	)
)

var registerOnce sync.Once

// Register は全メトリクスを Prometheus デフォルトレジストリに登録する。
func Register() {
	registerOnce.Do(func() {
		prometheus.MustRegister(RequestsTotal, RequestDuration, ActiveSessions, UpstreamErrors, CircuitBreakerTrips)
	})
}
