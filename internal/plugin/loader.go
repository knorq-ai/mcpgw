package plugin

import (
	"fmt"

	"github.com/knorq-ai/mcpgw/internal/config"
)

// LoadPlugins は設定に基づいてプラグインを生成・初期化する。
// いずれかのプラグインの生成または初期化に失敗した場合、
// それまでに生成済みのプラグインを Close してからエラーを返す。
func LoadPlugins(registry *Registry, configs []config.PluginConfig) ([]Plugin, error) {
	plugins := make([]Plugin, 0, len(configs))
	for _, cfg := range configs {
		p, err := registry.Create(cfg.Name)
		if err != nil {
			closeAll(plugins)
			return nil, fmt.Errorf("create plugin %q: %w", cfg.Name, err)
		}
		if err := p.Init(cfg.Config); err != nil {
			closeAll(plugins)
			return nil, fmt.Errorf("init plugin %q: %w", cfg.Name, err)
		}
		plugins = append(plugins, p)
	}
	return plugins, nil
}

// closeAll は生成済みプラグインを逆順に Close する。
func closeAll(plugins []Plugin) {
	for i := len(plugins) - 1; i >= 0; i-- {
		_ = plugins[i].Close()
	}
}
