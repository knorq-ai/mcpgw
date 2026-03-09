package plugin

import (
	"github.com/knorq-ai/mcpgw/internal/plugin/builtin/injection"
	"github.com/knorq-ai/mcpgw/internal/plugin/builtin/pii"
	"github.com/knorq-ai/mcpgw/internal/plugin/builtin/schema"
)

// RegisterBuiltins は組み込みプラグインを Registry に登録する。
func RegisterBuiltins(r *Registry) {
	r.Register("pii", func() Plugin { return pii.New() })
	r.Register("injection", func() Plugin { return injection.New() })
	r.Register("schema", func() Plugin { return schema.New() })
}
