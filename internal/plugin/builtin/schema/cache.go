package schema

import (
	"encoding/json"
	"sync"
)

// SchemaCache はツールの JSON Schema をキャッシュする。
type SchemaCache struct {
	mu      sync.RWMutex
	schemas map[string]json.RawMessage // ツール名 → JSON Schema
}

// NewSchemaCache は SchemaCache を生成する。
func NewSchemaCache() *SchemaCache {
	return &SchemaCache{
		schemas: make(map[string]json.RawMessage),
	}
}

// Get はツールのスキーマを取得する。
func (c *SchemaCache) Get(toolName string) (json.RawMessage, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.schemas[toolName]
	return s, ok
}

// Set はツールのスキーマを設定する。
func (c *SchemaCache) Set(toolName string, schema json.RawMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.schemas[toolName] = schema
}

// Count はキャッシュ済みスキーマ数を返す。
func (c *SchemaCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.schemas)
}
