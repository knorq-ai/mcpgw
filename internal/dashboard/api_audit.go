package dashboard

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/knorq-ai/mcpgw/internal/audit"
)

const (
	defaultAuditLimit = 50
	maxAuditFileSize  = 10 * 1024 * 1024 // 10MB
)

type auditResponse struct {
	Entries []audit.Entry `json:"entries"`
	Total   int           `json:"total"`
}

func handleAudit(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if path == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(auditResponse{Entries: []audit.Entry{}, Total: 0})
			return
		}

		q := r.URL.Query()
		limit := parseIntDefault(q.Get("limit"), defaultAuditLimit)
		offset := parseIntDefault(q.Get("offset"), 0)
		filterMethod := q.Get("method")
		filterAction := q.Get("action")
		filterDirection := q.Get("direction")
		filterSubject := q.Get("subject")
		filterUpstream := q.Get("upstream")
		filterTool := q.Get("tool")

		entries, err := readAuditLog(path, filterMethod, filterAction, filterDirection, filterSubject, filterUpstream, filterTool)
		if err != nil {
			// ファイルが存在しない場合は空レスポンス
			if os.IsNotExist(err) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(auditResponse{Entries: []audit.Entry{}, Total: 0})
				return
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		total := len(entries)

		// 新しい順に返す（ファイルは追記のため末尾が最新）
		reverseEntries(entries)

		// ページネーション
		if offset >= len(entries) {
			entries = []audit.Entry{}
		} else {
			end := offset + limit
			if end > len(entries) {
				end = len(entries)
			}
			entries = entries[offset:end]
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(auditResponse{Entries: entries, Total: total})
	}
}

func readAuditLog(path, filterMethod, filterAction, filterDirection, filterSubject, filterUpstream, filterTool string) ([]audit.Entry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxAuditFileSize {
		return readAuditLogTail(path, filterMethod, filterAction, filterDirection, filterSubject, filterUpstream, filterTool)
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
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if matchAuditFilter(entry, filterMethod, filterAction, filterDirection, filterSubject, filterUpstream, filterTool) {
			entries = append(entries, entry)
		}
	}
	return entries, scanner.Err()
}

// readAuditLogTail はファイルサイズが上限を超えた場合に末尾から読み取る。
func readAuditLogTail(path, filterMethod, filterAction, filterDirection, filterSubject, filterUpstream, filterTool string) ([]audit.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 末尾 maxAuditFileSize 分を読み取り
	info, _ := f.Stat()
	offset := info.Size() - maxAuditFileSize
	if offset < 0 {
		offset = 0
	}
	f.Seek(offset, 0)

	var entries []audit.Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// 先頭行は途中から読んでいる可能性があるのでスキップ
	first := true
	for scanner.Scan() {
		if first && offset > 0 {
			first = false
			continue
		}
		first = false

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry audit.Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if matchAuditFilter(entry, filterMethod, filterAction, filterDirection, filterSubject, filterUpstream, filterTool) {
			entries = append(entries, entry)
		}
	}
	return entries, scanner.Err()
}

func matchAuditFilter(e audit.Entry, method, action, direction, subject, upstream, tool string) bool {
	if method != "" && !strings.Contains(strings.ToLower(e.Method), strings.ToLower(method)) {
		return false
	}
	if action != "" && e.Action != action {
		return false
	}
	if direction != "" && e.Direction != direction {
		return false
	}
	if subject != "" && !strings.Contains(strings.ToLower(e.Subject), strings.ToLower(subject)) {
		return false
	}
	if upstream != "" && !strings.Contains(strings.ToLower(e.Upstream), strings.ToLower(upstream)) {
		return false
	}
	if tool != "" && !strings.Contains(strings.ToLower(e.ToolName), strings.ToLower(tool)) {
		return false
	}
	return true
}

func reverseEntries(entries []audit.Entry) {
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return def
	}
	return v
}
