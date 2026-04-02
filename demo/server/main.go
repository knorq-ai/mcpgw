// demo/server/main.go — デモ用脆弱 MCP サーバー。
// internal/ に依存しないスタンドアロンバイナリ。
// 安全なツール (echo, get_weather, calculate) と
// 危険なツール (exec_command, read_file, get_env, sql_query, send_email) を公開する。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

// ---------- JSON-RPC 型 ----------

type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ---------- MCP ツール定義 ----------

type toolSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]toolPropSchema `json:"properties,omitempty"`
	Required   []string                  `json:"required,omitempty"`
}

type toolPropSchema struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type toolEntry struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema toolSchema `json:"inputSchema"`
}

type toolDef struct {
	Entry   toolEntry
	Handler func(args json.RawMessage) (json.RawMessage, error)
}

func allTools() []toolDef {
	return []toolDef{
		// ---- Safe ----
		{
			Entry: toolEntry{
				Name:        "echo",
				Description: "Echo back the input text",
				InputSchema: toolSchema{
					Type: "object",
					Properties: map[string]toolPropSchema{
						"text": {Type: "string", Description: "Text to echo"},
					},
					Required: []string{"text"},
				},
			},
			Handler: func(args json.RawMessage) (json.RawMessage, error) {
				var p struct {
					Text string `json:"text"`
				}
				json.Unmarshal(args, &p)
				return json.Marshal(map[string]string{"echoed": p.Text})
			},
		},
		{
			Entry: toolEntry{
				Name:        "get_weather",
				Description: "Get current weather for a city",
				InputSchema: toolSchema{
					Type: "object",
					Properties: map[string]toolPropSchema{
						"city": {Type: "string", Description: "City name"},
					},
					Required: []string{"city"},
				},
			},
			Handler: func(args json.RawMessage) (json.RawMessage, error) {
				var p struct {
					City string `json:"city"`
				}
				json.Unmarshal(args, &p)
				return json.Marshal(map[string]any{
					"city":        p.City,
					"temperature": 22,
					"condition":   "sunny",
					"humidity":    45,
				})
			},
		},
		{
			Entry: toolEntry{
				Name:        "calculate",
				Description: "Evaluate a math expression",
				InputSchema: toolSchema{
					Type: "object",
					Properties: map[string]toolPropSchema{
						"expression": {Type: "string", Description: "Math expression to evaluate"},
					},
					Required: []string{"expression"},
				},
			},
			Handler: func(args json.RawMessage) (json.RawMessage, error) {
				var p struct {
					Expression string `json:"expression"`
				}
				json.Unmarshal(args, &p)
				return json.Marshal(map[string]string{
					"expression": p.Expression,
					"result":     "42",
				})
			},
		},
		// ---- Dangerous ----
		{
			Entry: toolEntry{
				Name:        "exec_command",
				Description: "Execute a shell command on the server",
				InputSchema: toolSchema{
					Type: "object",
					Properties: map[string]toolPropSchema{
						"command": {Type: "string", Description: "Shell command to execute"},
					},
					Required: []string{"command"},
				},
			},
			Handler: func(args json.RawMessage) (json.RawMessage, error) {
				var p struct {
					Command string `json:"command"`
				}
				json.Unmarshal(args, &p)
				return json.Marshal(map[string]string{
					"output": fmt.Sprintf("executed: %s\nuid=0(root) gid=0(root)", p.Command),
				})
			},
		},
		{
			Entry: toolEntry{
				Name:        "read_file",
				Description: "Read contents of any file on the server",
				InputSchema: toolSchema{
					Type: "object",
					Properties: map[string]toolPropSchema{
						"path": {Type: "string", Description: "File path to read"},
					},
					Required: []string{"path"},
				},
			},
			Handler: func(args json.RawMessage) (json.RawMessage, error) {
				var p struct {
					Path string `json:"path"`
				}
				json.Unmarshal(args, &p)
				return json.Marshal(map[string]string{
					"path":    p.Path,
					"content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
				})
			},
		},
		{
			Entry: toolEntry{
				Name:        "get_env",
				Description: "Read environment variables from the server",
				InputSchema: toolSchema{
					Type: "object",
					Properties: map[string]toolPropSchema{
						"name": {Type: "string", Description: "Environment variable name"},
					},
					Required: []string{"name"},
				},
			},
			Handler: func(args json.RawMessage) (json.RawMessage, error) {
				var p struct {
					Name string `json:"name"`
				}
				json.Unmarshal(args, &p)
				return json.Marshal(map[string]string{
					"name":  p.Name,
					"value": "sk-proj-FAKE-SECRET-KEY-12345",
				})
			},
		},
		{
			Entry: toolEntry{
				Name:        "sql_query",
				Description: "Execute SQL query on the database",
				InputSchema: toolSchema{
					Type: "object",
					Properties: map[string]toolPropSchema{
						"query": {Type: "string", Description: "SQL query to execute"},
					},
					Required: []string{"query"},
				},
			},
			Handler: func(args json.RawMessage) (json.RawMessage, error) {
				var p struct {
					Query string `json:"query"`
				}
				json.Unmarshal(args, &p)
				return json.Marshal(map[string]any{
					"query": p.Query,
					"rows": []map[string]string{
						{"id": "1", "username": "admin", "password_hash": "$2b$10$FAKE"},
					},
				})
			},
		},
		{
			Entry: toolEntry{
				Name:        "send_email",
				Description: "Send an email from the server",
				InputSchema: toolSchema{
					Type: "object",
					Properties: map[string]toolPropSchema{
						"to":      {Type: "string", Description: "Recipient email address"},
						"subject": {Type: "string", Description: "Email subject"},
						"body":    {Type: "string", Description: "Email body"},
					},
					Required: []string{"to", "subject", "body"},
				},
			},
			Handler: func(args json.RawMessage) (json.RawMessage, error) {
				var p struct {
					To      string `json:"to"`
					Subject string `json:"subject"`
				}
				json.Unmarshal(args, &p)
				return json.Marshal(map[string]string{
					"status":  "sent",
					"to":      p.To,
					"subject": p.Subject,
				})
			},
		},
	}
}

// ---------- サーバー ----------

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type server struct {
	mu       sync.Mutex
	sessions map[string]bool
	tools    []toolDef
}

func newServer() *server {
	return &server{
		sessions: make(map[string]bool),
		tools:    allTools(),
	}
}

func (s *server) validateSession(r *http.Request) bool {
	sid := r.Header.Get("Mcp-Session-Id")
	if sid == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[sid]
}

func (s *server) handleMessage(r *http.Request, msg jsonrpcMessage) (*jsonrpcMessage, map[string]string) {
	headers := map[string]string{}

	switch msg.Method {
	case "initialize":
		sid := generateSessionID()
		s.mu.Lock()
		s.sessions[sid] = true
		s.mu.Unlock()
		headers["Mcp-Session-Id"] = sid
		result, _ := json.Marshal(map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "demo-vulnerable-server", "version": "1.0.0"},
		})
		return &jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID, Result: result}, headers

	case "notifications/initialized":
		return nil, headers

	case "tools/list":
		if !s.validateSession(r) {
			return &jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID,
				Error: &jsonrpcError{Code: -32001, Message: "invalid session"}}, headers
		}
		var entries []toolEntry
		for _, t := range s.tools {
			entries = append(entries, t.Entry)
		}
		result, _ := json.Marshal(map[string]any{"tools": entries})
		return &jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID, Result: result}, headers

	case "tools/call":
		if !s.validateSession(r) {
			return &jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID,
				Error: &jsonrpcError{Code: -32001, Message: "invalid session"}}, headers
		}
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		json.Unmarshal(msg.Params, &params)

		var handler func(json.RawMessage) (json.RawMessage, error)
		for _, t := range s.tools {
			if t.Entry.Name == params.Name {
				handler = t.Handler
				break
			}
		}
		if handler == nil {
			return &jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID,
				Error: &jsonrpcError{Code: -32602, Message: "unknown tool: " + params.Name}}, headers
		}

		handlerResult, err := handler(params.Arguments)
		if err != nil {
			return &jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID,
				Error: &jsonrpcError{Code: -32603, Message: err.Error()}}, headers
		}

		textContent, _ := json.Marshal([]map[string]string{
			{"type": "text", "text": string(handlerResult)},
		})
		result, _ := json.Marshal(map[string]json.RawMessage{"content": textContent})
		return &jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID, Result: result}, headers

	default:
		return &jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID,
			Error: &jsonrpcError{Code: -32601, Message: "Method not found"}}, headers
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		trimmed := strings.TrimSpace(string(body))

		// バッチリクエスト
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var rawMsgs []json.RawMessage
			if err := json.Unmarshal([]byte(trimmed), &rawMsgs); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
			var responses []json.RawMessage
			for _, raw := range rawMsgs {
				var msg jsonrpcMessage
				if err := json.Unmarshal(raw, &msg); err != nil {
					continue
				}
				resp, hdrs := s.handleMessage(r, msg)
				for k, v := range hdrs {
					w.Header().Set(k, v)
				}
				if resp != nil {
					data, _ := json.Marshal(resp)
					responses = append(responses, data)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(responses)
			return
		}

		// 単一リクエスト
		var msg jsonrpcMessage
		if err := json.Unmarshal([]byte(trimmed), &msg); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		resp, hdrs := s.handleMessage(r, msg)
		for k, v := range hdrs {
			w.Header().Set(k, v)
		}
		if resp == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)

	case http.MethodDelete:
		sid := r.Header.Get("Mcp-Session-Id")
		if sid == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		existed := s.sessions[sid]
		delete(s.sessions, sid)
		s.mu.Unlock()
		if !existed {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	addr := ":8080"
	if v := os.Getenv("DEMO_SERVER_ADDR"); v != "" {
		addr = v
	}

	srv := newServer()
	log.Printf("demo-server listening on %s (tools: %d)", addr, len(srv.tools))
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
