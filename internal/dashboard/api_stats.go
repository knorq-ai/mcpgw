package dashboard

import (
	"encoding/json"
	"net/http"
	"sort"

	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/client_golang/prometheus"
)

type statsResponse struct {
	RequestsTotal      float64            `json:"requests_total"`
	RequestsBlocked    float64            `json:"requests_blocked"`
	BlockedRate        float64            `json:"blocked_rate"`
	ActiveSessions     float64            `json:"active_sessions"`
	UpstreamErrors     float64            `json:"upstream_errors"`
	CircuitBreakerTrips float64           `json:"circuit_breaker_trips"`
	LatencyP50         float64            `json:"latency_p50"`
	LatencyP95         float64            `json:"latency_p95"`
	LatencyP99         float64            `json:"latency_p99"`
	RequestsByMethod   map[string]float64 `json:"requests_by_method"`
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	index := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		index[f.GetName()] = f
	}

	var total, blocked float64
	byMethod := make(map[string]float64)

	if fam, ok := index["mcpgw_requests_total"]; ok {
		for _, m := range fam.GetMetric() {
			v := m.GetCounter().GetValue()
			total += v
			var method, action string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "method":
					method = lp.GetValue()
				case "action":
					action = lp.GetValue()
				}
			}
			if action == "block" {
				blocked += v
			}
			if method != "" {
				byMethod[method] += v
			}
		}
	}

	var blockedRate float64
	if total > 0 {
		blockedRate = blocked / total
	}

	resp := statsResponse{
		RequestsTotal:       total,
		RequestsBlocked:     blocked,
		BlockedRate:         blockedRate,
		ActiveSessions:      gaugeValue(index, "mcpgw_active_sessions"),
		UpstreamErrors:      counterValue(index, "mcpgw_upstream_errors_total"),
		CircuitBreakerTrips: counterValue(index, "mcpgw_circuit_breaker_trips_total"),
		LatencyP50:          histogramQuantile(index, "mcpgw_request_duration_seconds", 0.50),
		LatencyP95:          histogramQuantile(index, "mcpgw_request_duration_seconds", 0.95),
		LatencyP99:          histogramQuantile(index, "mcpgw_request_duration_seconds", 0.99),
		RequestsByMethod:    byMethod,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func gaugeValue(index map[string]*dto.MetricFamily, name string) float64 {
	fam, ok := index[name]
	if !ok || len(fam.GetMetric()) == 0 {
		return 0
	}
	return fam.GetMetric()[0].GetGauge().GetValue()
}

func counterValue(index map[string]*dto.MetricFamily, name string) float64 {
	fam, ok := index[name]
	if !ok || len(fam.GetMetric()) == 0 {
		return 0
	}
	return fam.GetMetric()[0].GetCounter().GetValue()
}

// histogramQuantile は Prometheus ヒストグラムから指定パーセンタイル値を算出する。
func histogramQuantile(index map[string]*dto.MetricFamily, name string, q float64) float64 {
	fam, ok := index[name]
	if !ok {
		return 0
	}

	// 全ラベル組み合わせのバケットを合算
	merged := make(map[float64]uint64)
	var totalCount uint64

	for _, m := range fam.GetMetric() {
		h := m.GetHistogram()
		if h == nil {
			continue
		}
		totalCount += h.GetSampleCount()
		for _, b := range h.GetBucket() {
			merged[b.GetUpperBound()] += b.GetCumulativeCount()
		}
	}

	if totalCount == 0 {
		return 0
	}

	type bucket struct {
		bound float64
		count uint64
	}
	buckets := make([]bucket, 0, len(merged))
	for b, c := range merged {
		buckets = append(buckets, bucket{bound: b, count: c})
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].bound < buckets[j].bound
	})

	rank := q * float64(totalCount)
	for _, b := range buckets {
		if float64(b.count) >= rank {
			return b.bound
		}
	}
	if len(buckets) > 0 {
		return buckets[len(buckets)-1].bound
	}
	return 0
}
