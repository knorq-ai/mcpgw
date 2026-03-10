package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/knorq-ai/mcpgw/internal/servereval"
)

func handleServers(store *servereval.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		servers := store.List()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"servers": servers})
	}
}

func handleServerAction(store *servereval.Store, status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Upstream string `json:"upstream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Upstream == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if !store.UpdateStatus(req.Upstream, status) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}
