package policy

// PolicyFile はポリシー YAML のトップレベル構造。
type PolicyFile struct {
	Version          string   `yaml:"version"`
	Mode             string   `yaml:"mode"`                         // "enforce" or "audit"
	Rules            []Rule   `yaml:"rules"`
	ResponsePatterns []string `yaml:"response_patterns,omitempty"`  // S→C レスポンスボディの正規表現パターン
	AllowedTools     []string `yaml:"allowed_tools,omitempty"`      // tools/list で許可するツール名（glob）
}

// Rule はポリシールール。first-match-wins で評価される。
type Rule struct {
	Name   string `yaml:"name"`
	Match  Match  `yaml:"match"`
	Action string `yaml:"action"`         // "allow" or "deny"
	Mode   string `yaml:"mode,omitempty"` // "enforce" or "audit"（未指定時はファイルレベルを継承）
}

// Match はルールのマッチング条件。
type Match struct {
	Methods          []string            `yaml:"methods"`                        // JSON-RPC メソッド名（glob パターン）
	Tools            []string            `yaml:"tools,omitempty"`                // MCP ツール名（glob パターン, tools/call 専用）
	Subjects         []string            `yaml:"subjects,omitempty"`             // Identity subject（glob パターン）
	Roles            []string            `yaml:"roles,omitempty"`                // ロール名（glob パターン）
	Arguments        map[string][]string `yaml:"arguments,omitempty"`            // ツール引数パターン（glob, tools/call 専用）
	ArgumentPatterns map[string][]string `yaml:"argument_patterns,omitempty"`    // ツール引数パターン（正規表現, tools/call 専用）
}
