package plugin

import (
	"fmt"
	"sync"
)

// Factory はプラグインのインスタンスを生成するファクトリ関数。
type Factory func() Plugin

// Registry はプラグイン名からファクトリ関数へのマッピングを管理する。
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry は空の Registry を生成する。
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]Factory),
	}
}

// Register はプラグイン名にファクトリ関数を登録する。
// 同名が既に登録済みの場合は上書きする。
func (r *Registry) Register(name string, factory Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

// Create は指定された名前のプラグインを生成する。
// 未登録の名前を指定した場合はエラーを返す。
func (r *Registry) Create(name string) (Plugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown plugin: %q", name)
	}
	return f(), nil
}
