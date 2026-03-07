package policy

// PolicyFile はポリシー YAML のトップレベル構造。
type PolicyFile struct {
	Version string `yaml:"version"`
	Mode    string `yaml:"mode"` // "enforce" or "audit"
	Rules   []Rule `yaml:"rules"`
}

// Rule はポリシールール。first-match-wins で評価される。
type Rule struct {
	Name   string `yaml:"name"`
	Match  Match  `yaml:"match"`
	Action string `yaml:"action"` // "allow" or "deny"
}

// Match はルールのマッチング条件。
type Match struct {
	Methods  []string `yaml:"methods"`            // JSON-RPC メソッド名（glob パターン）
	Tools    []string `yaml:"tools,omitempty"`     // MCP ツール名（glob パターン, tools/call 専用）
	Subjects []string `yaml:"subjects,omitempty"`  // Identity subject（glob パターン）
}
