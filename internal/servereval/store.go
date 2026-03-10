package servereval

import (
	"sync"
	"time"
)

// ServerInfo は評価済み MCP サーバーの情報。
type ServerInfo struct {
	Upstream     string     `json:"upstream"`
	ServerName   string     `json:"server_name,omitempty"`
	Tools        []ToolInfo `json:"tools"`
	RiskLevel    string     `json:"risk_level"`
	RiskScore    float64    `json:"risk_score"`
	Status       string     `json:"status"` // "approved"|"denied"|"pending"
	DiscoveredAt time.Time  `json:"discovered_at"`
	EvaluatedAt  time.Time  `json:"evaluated_at"`
}

// ToolInfo はツールの情報。
type ToolInfo struct {
	Name      string `json:"name"`
	RiskLevel string `json:"risk_level"`
}

// Store は評価済みサーバー情報のインメモリストア。
type Store struct {
	mu      sync.RWMutex
	servers map[string]*ServerInfo
}

// NewStore は新しい Store を生成する。
func NewStore() *Store {
	return &Store{servers: make(map[string]*ServerInfo)}
}

// Get は upstream URL に対応するサーバー情報を返す。
func (s *Store) Get(upstream string) *ServerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.servers[upstream]
}

// Set はサーバー情報を格納する。
func (s *Store) Set(info *ServerInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers[info.Upstream] = info
}

// List は全サーバー情報のスナップショットを返す。
func (s *Store) List() []*ServerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*ServerInfo, 0, len(s.servers))
	for _, info := range s.servers {
		result = append(result, info)
	}
	return result
}

// UpdateStatus はサーバーのステータスを更新する。存在しない場合は false を返す。
func (s *Store) UpdateStatus(upstream, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.servers[upstream]
	if !ok {
		return false
	}
	info.Status = status
	return true
}
