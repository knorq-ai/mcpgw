package dashboard

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/knorq-ai/mcpgw/internal/audit"
)

// analyticsGroup は集計結果の1グループ。
type analyticsGroup struct {
	Key        string   `json:"key"`
	Total      int      `json:"total"`
	Passed     int      `json:"passed"`
	Blocked    int      `json:"blocked"`
	BlockRate  float64  `json:"block_rate"`
	TopTools   []string `json:"top_tools"`
	TopMethods []string `json:"top_methods"`
}

type analyticsResponse struct {
	Groups []analyticsGroup `json:"groups"`
	Period struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"period"`
}

func handleAnalytics(path, dimension string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		q := r.URL.Query()
		fromStr := q.Get("from")
		toStr := q.Get("to")

		var from, to time.Time
		if fromStr != "" {
			if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
				from = t
			}
		}
		if toStr != "" {
			if t, err := time.Parse(time.RFC3339, toStr); err == nil {
				to = t
			}
		}

		entries, err := scanAuditLog(path, func(e audit.Entry) bool {
			if !from.IsZero() && e.Timestamp.Before(from) {
				return false
			}
			if !to.IsZero() && e.Timestamp.After(to) {
				return false
			}
			return true
		})
		if err != nil {
			if os.IsNotExist(err) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(analyticsResponse{Groups: []analyticsGroup{}})
				return
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		groups := aggregate(entries, dimension)

		resp := analyticsResponse{Groups: groups}
		if fromStr != "" {
			resp.Period.From = fromStr
		}
		if toStr != "" {
			resp.Period.To = toStr
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func scanAuditLog(path string, filter func(audit.Entry) bool) ([]audit.Entry, error) {
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []audit.Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry audit.Entry
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		if filter(entry) {
			entries = append(entries, entry)
		}
	}
	return entries, scanner.Err()
}

func aggregate(entries []audit.Entry, dimension string) []analyticsGroup {
	type groupData struct {
		total       int
		passed      int
		blocked     int
		toolCount   map[string]int
		methodCount map[string]int
	}

	groups := map[string]*groupData{}

	for _, e := range entries {
		key := extractKey(e, dimension)
		if key == "" {
			key = "(unknown)"
		}
		g, ok := groups[key]
		if !ok {
			g = &groupData{
				toolCount:   map[string]int{},
				methodCount: map[string]int{},
			}
			groups[key] = g
		}
		g.total++
		if e.Action == "block" {
			g.blocked++
		} else {
			g.passed++
		}
		if e.ToolName != "" {
			g.toolCount[e.ToolName]++
		}
		if e.Method != "" {
			g.methodCount[e.Method]++
		}
	}

	result := make([]analyticsGroup, 0, len(groups))
	for key, g := range groups {
		blockRate := 0.0
		if g.total > 0 {
			blockRate = float64(g.blocked) / float64(g.total)
		}
		result = append(result, analyticsGroup{
			Key:        key,
			Total:      g.total,
			Passed:     g.passed,
			Blocked:    g.blocked,
			BlockRate:  blockRate,
			TopTools:   topN(g.toolCount, 5),
			TopMethods: topN(g.methodCount, 5),
		})
	}

	// Total 降順でソート
	sort.Slice(result, func(i, j int) bool {
		return result[i].Total > result[j].Total
	})

	return result
}

func extractKey(e audit.Entry, dimension string) string {
	switch dimension {
	case "upstream":
		return e.Upstream
	case "subject":
		return e.Subject
	case "tool":
		return e.ToolName
	case "threat":
		return e.ThreatType
	default:
		return ""
	}
}

func topN(counts map[string]int, n int) []string {
	type kv struct {
		key   string
		count int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	result := make([]string, len(sorted))
	for i, kv := range sorted {
		result[i] = kv.key
	}
	return result
}
