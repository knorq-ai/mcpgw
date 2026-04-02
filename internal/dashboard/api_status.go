package dashboard

import (
	"encoding/json"
	"net/http"
)

type statusResponse struct {
	Upstream       string `json:"upstream"`
	UpstreamReady  bool   `json:"upstream_ready"`
	CircuitBreaker string `json:"circuit_breaker"`
	ActiveSessions int    `json:"active_sessions"`
}

func handleStatus(provider StatusProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if provider == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(statusResponse{})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(statusResponse{
			Upstream:       provider.Upstream(),
			UpstreamReady:  provider.UpstreamReady(),
			CircuitBreaker: provider.CircuitBreakerState(),
			ActiveSessions: provider.ActiveSessionCount(),
		})
	}
}
