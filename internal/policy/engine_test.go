package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPolicy(rules []Rule) *Engine {
	return NewEngine(&PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules:   rules,
	})
}

func TestEngineAllowAll(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	d := engine.Evaluate("tools/list", nil, "")
	assert.True(t, d.Allow)
	assert.Equal(t, "allow-all", d.RuleName)

	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec"}`), "")
	assert.True(t, d.Allow)
}

func TestEngineDenySpecificTool(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "deny-exec", Match: Match{
			Methods: []string{"tools/call"},
			Tools:   []string{"exec_*", "run_command"},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// exec_cmd はブロックされる
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "deny-exec", d.RuleName)

	// run_command はブロックされる
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"run_command"}`), "")
	assert.False(t, d.Allow)

	// read_file は許可される（ツールパターンにマッチしない → deny-exec スキップ → allow-all）
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file"}`), "")
	assert.True(t, d.Allow)
	assert.Equal(t, "allow-all", d.RuleName)

	// tools/list は許可される（メソッドが tools/call ではない）
	d = engine.Evaluate("tools/list", nil, "")
	assert.True(t, d.Allow)
}

func TestEngineFirstMatchWins(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "deny-all-calls", Match: Match{Methods: []string{"tools/call"}}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// tools/call は最初のルールでブロック
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"safe_tool"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "deny-all-calls", d.RuleName)

	// initialize は2番目のルールで許可
	d = engine.Evaluate("initialize", nil, "")
	assert.True(t, d.Allow)
}

func TestEngineImplicitDeny(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "allow-init", Match: Match{Methods: []string{"initialize"}}, Action: "allow"},
	})

	// initialize はルールで許可
	d := engine.Evaluate("initialize", nil, "")
	assert.True(t, d.Allow)

	// tools/list はどのルールにもマッチしない → 暗黙の deny
	d = engine.Evaluate("tools/list", nil, "")
	assert.False(t, d.Allow)
	assert.Equal(t, "(implicit-deny)", d.RuleName)
}

func TestEngineMethodGlob(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "deny-tools", Match: Match{Methods: []string{"tools/*"}}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	d := engine.Evaluate("tools/call", nil, "")
	assert.False(t, d.Allow)

	d = engine.Evaluate("tools/list", nil, "")
	assert.False(t, d.Allow)

	d = engine.Evaluate("initialize", nil, "")
	assert.True(t, d.Allow)

	// notifications/initialized — "/" 含むが "tools/*" にはマッチしない
	d = engine.Evaluate("notifications/initialized", nil, "")
	assert.True(t, d.Allow)
}

func TestEngineAuditMode(t *testing.T) {
	engine := NewEngine(&PolicyFile{
		Version: "v1",
		Mode:    "audit",
		Rules: []Rule{
			{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
			{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})

	// deny 判定は出るが、audit モードなのでブロックはしない
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "audit", d.Mode)
}

func TestEngineToolsCallWithoutParams(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// params が nil の場合、ツール名抽出できない → deny-exec にマッチしない → allow-all
	d := engine.Evaluate("tools/call", nil, "")
	assert.True(t, d.Allow)
}

func TestEngineToolsCallWithMalformedParams(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// 不正な JSON params
	d := engine.Evaluate("tools/call", json.RawMessage(`not json`), "")
	assert.True(t, d.Allow)
}

func TestExtractToolName(t *testing.T) {
	tests := []struct {
		name   string
		params json.RawMessage
		want   string
	}{
		{"normal", json.RawMessage(`{"name":"read_file","arguments":{}}`), "read_file"},
		{"no name", json.RawMessage(`{"arguments":{}}`), ""},
		{"empty", nil, ""},
		{"invalid json", json.RawMessage(`invalid`), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExtractToolName(tt.params))
		})
	}
}

func TestMatchMethods(t *testing.T) {
	assert.True(t, matchMethods([]string{"*"}, "tools/call"))
	assert.True(t, matchMethods([]string{"tools/*"}, "tools/call"))
	assert.False(t, matchMethods([]string{"tools/*"}, "initialize"))
	assert.True(t, matchMethods([]string{"initialize", "tools/*"}, "initialize"))
}

func TestMatchTools(t *testing.T) {
	assert.True(t, matchTools([]string{"exec_*"}, "exec_cmd"))
	assert.True(t, matchTools([]string{"exec_*", "run_*"}, "run_command"))
	assert.False(t, matchTools([]string{"exec_*"}, "read_file"))
	assert.False(t, matchTools([]string{"exec_*"}, ""))
}

func TestGlobMatchLongInput(t *testing.T) {
	// maxGlobInput (512) を超える入力は常に false
	long := strings.Repeat("a", maxGlobInput+1)
	assert.False(t, globMatch("*", long))

	// ちょうど maxGlobInput はマッチする
	exact := strings.Repeat("a", maxGlobInput)
	assert.True(t, globMatch("*", exact))
}

func TestGlobMatchAdversarialPatterns(t *testing.T) {
	// 多数の '*' と長い入力 — O(n*m) アルゴリズムが爆発しないことを確認
	pattern := strings.Repeat("*a", 50) + "*"
	input := strings.Repeat("a", 50)
	// 計算量が制御されていれば瞬時に完了する
	_ = globMatch(pattern, input)

	// マッチしないケースでも爆発しない
	noMatch := strings.Repeat("b", 100)
	assert.False(t, globMatch(pattern, noMatch))
}

func TestGlobMatchPatterns(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"*", "a/b/c", true},
		{"?", "a", true},
		{"?", "", false},
		{"?", "ab", false},
		{"a*b", "ab", true},
		{"a*b", "axyzb", true},
		{"a*b", "axyzc", false},
		{"tools/*", "tools/call", true},
		{"tools/*", "tools/list", true},
		{"tools/*", "initialize", false},
		{"exec_*", "exec_cmd", true},
		{"exec_*", "exec_", true},
		{"exec_*", "exec", false},
		{"**", "anything", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, globMatch(tt.pattern, tt.input),
				"globMatch(%q, %q)", tt.pattern, tt.input)
		})
	}
}

func TestEngineSubjectMatch(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "admin-exec", Match: Match{
			Methods:  []string{"tools/call"},
			Tools:    []string{"exec_*"},
			Subjects: []string{"admin-*"},
		}, Action: "allow"},
		{Name: "deny-exec", Match: Match{
			Methods: []string{"tools/call"},
			Tools:   []string{"exec_*"},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// admin-alice → admin-exec にマッチ → 許可
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "admin-alice")
	assert.True(t, d.Allow)
	assert.Equal(t, "admin-exec", d.RuleName)

	// user-bob → admin-exec の subjects にマッチしない → deny-exec にフォールスルー
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "user-bob")
	assert.False(t, d.Allow)
	assert.Equal(t, "deny-exec", d.RuleName)
}

func TestEngineSubjectNoAuth(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "admin-only", Match: Match{
			Methods:  []string{"tools/call"},
			Subjects: []string{"admin-*"},
		}, Action: "allow"},
		{Name: "deny-all", Match: Match{Methods: []string{"*"}}, Action: "deny"},
	})

	// subject 空（未認証） → subjects 指定ルールにマッチしない → deny-all
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "deny-all", d.RuleName)
}

func TestEngineSubjectNotSpecified(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// subjects 未指定のルール → 全 subject にマッチ（後方互換）
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "any-user")
	assert.True(t, d.Allow)

	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "")
	assert.True(t, d.Allow)
}

func TestMatchSubjects(t *testing.T) {
	assert.True(t, matchSubjects([]string{"admin-*"}, "admin-alice"))
	assert.False(t, matchSubjects([]string{"admin-*"}, "user-bob"))
	assert.False(t, matchSubjects([]string{"admin-*"}, ""))
	assert.True(t, matchSubjects([]string{"*"}, "anyone"))
	assert.False(t, matchSubjects([]string{"*"}, ""))
}

func TestEngineArgumentMatch(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "block-sensitive-reads", Match: Match{
			Methods:   []string{"tools/call"},
			Tools:     []string{"read_file"},
			Arguments: map[string][]string{"path": {"/etc/*", "*.env", "*.pem"}},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// /etc/passwd → ブロック
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/passwd"}}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "block-sensitive-reads", d.RuleName)

	// .env → ブロック
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file","arguments":{"path":"/app/.env"}}`), "")
	assert.False(t, d.Allow)

	// 安全パス → 許可（引数パターンにマッチしない → ルールスキップ → allow-all）
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file","arguments":{"path":"/home/user/doc.txt"}}`), "")
	assert.True(t, d.Allow)
	assert.Equal(t, "allow-all", d.RuleName)
}

func TestEngineArgumentMultiPatternOR(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "block-cmds", Match: Match{
			Methods:   []string{"tools/call"},
			Tools:     []string{"exec_command"},
			Arguments: map[string][]string{"command": {"*rm *", "*sudo*", "*chmod*"}},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// rm → ブロック（OR: 最初のパターン）
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_command","arguments":{"command":"rm -rf /tmp"}}`), "")
	assert.False(t, d.Allow)

	// sudo → ブロック（OR: 2番目のパターン）
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_command","arguments":{"command":"sudo reboot"}}`), "")
	assert.False(t, d.Allow)

	// ls → 許可（どのパターンにもマッチしない）
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_command","arguments":{"command":"ls -la"}}`), "")
	assert.True(t, d.Allow)
}

func TestEngineArgumentMultiArgAND(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "block-specific", Match: Match{
			Methods:   []string{"tools/call"},
			Tools:     []string{"send_email"},
			Arguments: map[string][]string{
				"to":      {"*@evil.com"},
				"subject": {"*urgent*"},
			},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// 両方マッチ → ブロック（AND）
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"send_email","arguments":{"to":"x@evil.com","subject":"urgent request"}}`), "")
	assert.False(t, d.Allow)

	// to のみマッチ → 許可（AND の片方不成立）
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"send_email","arguments":{"to":"x@evil.com","subject":"hello"}}`), "")
	assert.True(t, d.Allow)

	// subject のみマッチ → 許可
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"send_email","arguments":{"to":"x@good.com","subject":"urgent request"}}`), "")
	assert.True(t, d.Allow)
}

func TestEngineArgumentMissingArg(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "block-reads", Match: Match{
			Methods:   []string{"tools/call"},
			Tools:     []string{"read_file"},
			Arguments: map[string][]string{"path": {"/etc/*"}},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// 引数なし → fail-closed (マッチしない → ルールスキップ → allow-all)
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file","arguments":{}}`), "")
	assert.True(t, d.Allow)

	// params.arguments 自体がない → fail-closed
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file"}`), "")
	assert.True(t, d.Allow)

	// params が nil → fail-closed
	d = engine.Evaluate("tools/call", nil, "")
	assert.True(t, d.Allow)
}

func TestEngineArgumentNonStringStringify(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "block-port", Match: Match{
			Methods:   []string{"tools/call"},
			Tools:     []string{"connect"},
			Arguments: map[string][]string{"port": {"22", "23"}},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// 数値 22 → 文字列 "22" にマッチ
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"connect","arguments":{"port":22}}`), "")
	assert.False(t, d.Allow)

	// 数値 80 → マッチしない → 許可
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"connect","arguments":{"port":80}}`), "")
	assert.True(t, d.Allow)
}

func TestStringifyJSONValue(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{"string", json.RawMessage(`"hello"`), "hello"},
		{"integer", json.RawMessage(`42`), "42"},
		{"float", json.RawMessage(`3.14`), "3.14"},
		{"bool true", json.RawMessage(`true`), "true"},
		{"bool false", json.RawMessage(`false`), "false"},
		{"null", json.RawMessage(`null`), ""},
		{"array", json.RawMessage(`[1,2]`), "[1,2]"},
		{"empty", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, stringifyJSONValue(tt.raw))
		})
	}
}

func TestExtractArguments(t *testing.T) {
	tests := []struct {
		name   string
		params json.RawMessage
		want   map[string]string
	}{
		{"normal", json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/passwd"}}`), map[string]string{"path": "/etc/passwd"}},
		{"numeric", json.RawMessage(`{"name":"connect","arguments":{"port":22}}`), map[string]string{"port": "22"}},
		{"no arguments", json.RawMessage(`{"name":"read_file"}`), nil},
		{"empty arguments", json.RawMessage(`{"name":"read_file","arguments":{}}`), nil},
		{"nil params", nil, nil},
		{"invalid json", json.RawMessage(`invalid`), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractArguments(tt.params))
		})
	}
}

func TestMatchArguments(t *testing.T) {
	tests := []struct {
		name     string
		patterns map[string][]string
		args     map[string]string
		want     bool
	}{
		{"single match", map[string][]string{"path": {"/etc/*"}}, map[string]string{"path": "/etc/passwd"}, true},
		{"single no match", map[string][]string{"path": {"/etc/*"}}, map[string]string{"path": "/home/user/file"}, false},
		{"or match second", map[string][]string{"path": {"/etc/*", "*.env"}}, map[string]string{"path": "/app/.env"}, true},
		{"and both match", map[string][]string{"a": {"x*"}, "b": {"y*"}}, map[string]string{"a": "xx", "b": "yy"}, true},
		{"and one fail", map[string][]string{"a": {"x*"}, "b": {"y*"}}, map[string]string{"a": "xx", "b": "zz"}, false},
		{"missing arg", map[string][]string{"path": {"/etc/*"}}, map[string]string{}, false},
		{"nil args", map[string][]string{"path": {"/etc/*"}}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchArguments(tt.patterns, tt.args))
		})
	}
}

func TestLoadAndEvaluateArgs(t *testing.T) {
	pf, err := Load("../../testdata/policy_deny_args.yaml")
	require.NoError(t, err)

	engine := NewEngine(pf)

	// /etc/passwd → ブロック
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/passwd"}}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "block-sensitive-reads", d.RuleName)

	// 安全パス → 許可
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file","arguments":{"path":"/home/user/readme.txt"}}`), "")
	assert.True(t, d.Allow)
	assert.Equal(t, "allow-all", d.RuleName)

	// 危険コマンド → ブロック
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_command","arguments":{"command":"sudo rm -rf /"}}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "block-dangerous-commands", d.RuleName)

	// 安全コマンド → 許可
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_command","arguments":{"command":"ls -la"}}`), "")
	assert.True(t, d.Allow)
}

func TestEngineResponsePatterns(t *testing.T) {
	engine := NewEngine(&PolicyFile{
		Version:          "v1",
		Mode:             "enforce",
		Rules:            []Rule{{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"}},
		ResponsePatterns: []string{`(?i)api[_-]?key`, `(?i)secret`},
	})

	patterns := engine.ResponsePatterns()
	assert.Len(t, patterns, 2)
	assert.True(t, patterns[0].MatchString("my API_KEY is here"))
	assert.False(t, patterns[0].MatchString("no match"))
}

func TestEngineAllowedTools(t *testing.T) {
	engine := NewEngine(&PolicyFile{
		Version:      "v1",
		Mode:         "enforce",
		Rules:        []Rule{{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"}},
		AllowedTools: []string{"read_*", "write_*"},
	})

	assert.Equal(t, []string{"read_*", "write_*"}, engine.AllowedTools())
}

func TestGlobMatchPublic(t *testing.T) {
	assert.True(t, GlobMatch("read_*", "read_file"))
	assert.False(t, GlobMatch("read_*", "exec_cmd"))
}

func TestValidateResponsePatternsInvalidRegex(t *testing.T) {
	_, err := Parse([]byte(`
version: v1
mode: enforce
response_patterns:
  - "[invalid"
rules:
  - name: allow-all
    match:
      methods: ["*"]
    action: allow
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response_patterns")
}

func TestEngineResponsePatternsCompile(t *testing.T) {
	engine := NewEngine(&PolicyFile{
		Version:          "v1",
		Mode:             "enforce",
		Rules:            []Rule{{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"}},
		ResponsePatterns: []string{`password\s*=\s*\S+`},
	})

	patterns := engine.ResponsePatterns()
	require.Len(t, patterns, 1)
	assert.IsType(t, &regexp.Regexp{}, patterns[0])
}

func TestValidateArgumentsRequiresToolsCall(t *testing.T) {
	// arguments 指定時に methods に tools/call が含まれない → エラー
	_, err := Parse([]byte(`
version: v1
mode: enforce
rules:
  - name: bad-rule
    match:
      methods: ["tools/list"]
      arguments:
        path: ["/etc/*"]
    action: deny
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "arguments requires methods to include \"tools/call\"")
}

func TestValidateArgumentsEmptyPatterns(t *testing.T) {
	// 空パターンリスト → エラー
	_, err := Parse([]byte(`
version: v1
mode: enforce
rules:
  - name: bad-rule
    match:
      methods: ["tools/call"]
      arguments:
        path: []
    action: deny
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must have at least one pattern")
}

func TestPathTraversalCanonicalization(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "block-etc", Match: Match{
			Methods:   []string{"tools/call"},
			Tools:     []string{"read_file"},
			Arguments: map[string][]string{"path": {"/etc/*"}},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	tests := []struct {
		name  string
		path  string
		allow bool
	}{
		{"direct /etc/passwd", "/etc/passwd", false},
		{"traversal /var/../etc/passwd", "/var/../etc/passwd", false},
		{"double traversal /a/b/../../etc/passwd", "/a/b/../../etc/passwd", false},
		{"traversal /../etc/shadow", "/../etc/shadow", false},
		{"safe path no traversal", "/home/user/doc.txt", true},
		{"relative traversal ../etc/passwd", "../etc/passwd", true}, // Clean → "../etc/passwd" — /etc/* にマッチしない
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := json.RawMessage(fmt.Sprintf(`{"name":"read_file","arguments":{"path":%q}}`, tt.path))
			d := engine.Evaluate("tools/call", params, "")
			assert.Equal(t, tt.allow, d.Allow, "path=%q", tt.path)
		})
	}
}

func TestPerRuleAuditMode(t *testing.T) {
	// ファイルレベル enforce、ルールレベル audit
	engine := NewEngine(&PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []Rule{
			{Name: "audit-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny", Mode: "audit"},
			{Name: "deny-rm", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"rm_*"}}, Action: "deny"},
			{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})

	// audit-exec: deny だが mode=audit → ブロックされない
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "audit", d.Mode)

	// deny-rm: deny で mode 未指定 → ファイルレベル enforce を継承 → ブロック
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"rm_file"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "enforce", d.Mode)
}

func TestPerRuleModeInheritance(t *testing.T) {
	// ファイルレベル audit、ルールレベル enforce
	engine := NewEngine(&PolicyFile{
		Version: "v1",
		Mode:    "audit",
		Rules: []Rule{
			{Name: "strict-deny", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"dangerous_*"}}, Action: "deny", Mode: "enforce"},
			{Name: "deny-other", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
			{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})

	// strict-deny: mode=enforce → ブロック
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"dangerous_cmd"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "enforce", d.Mode)

	// deny-other: mode 未指定 → ファイルレベル audit を継承
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "audit", d.Mode)
}

func TestEngineArgumentPatternRegex(t *testing.T) {
	engine := NewEngine(&PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []Rule{
			{Name: "block-sql-injection", Match: Match{
				Methods:          []string{"tools/call"},
				Tools:            []string{"query_db"},
				ArgumentPatterns: map[string][]string{"query": {`(?i)(DROP|DELETE|TRUNCATE)\s+TABLE`}},
			}, Action: "deny"},
			{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})

	// DROP TABLE → ブロック
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"query_db","arguments":{"query":"DROP TABLE users"}}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "block-sql-injection", d.RuleName)

	// delete table（大文字小文字無視） → ブロック
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"query_db","arguments":{"query":"delete table sessions"}}`), "")
	assert.False(t, d.Allow)

	// SELECT → 許可
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"query_db","arguments":{"query":"SELECT * FROM users"}}`), "")
	assert.True(t, d.Allow)
}

func TestEngineArgumentPatternRegexWithGlob(t *testing.T) {
	// glob と regex 両方指定 — 両方マッチで通過
	engine := NewEngine(&PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []Rule{
			{Name: "block-path-and-content", Match: Match{
				Methods:          []string{"tools/call"},
				Tools:            []string{"write_file"},
				Arguments:        map[string][]string{"path": {"/etc/*"}},
				ArgumentPatterns: map[string][]string{"content": {`(?i)password\s*=`}},
			}, Action: "deny"},
			{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
		},
	})

	// 両方マッチ → ブロック
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"write_file","arguments":{"path":"/etc/config","content":"password = secret"}}`), "")
	assert.False(t, d.Allow)

	// path のみマッチ → スキップ → allow-all
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"write_file","arguments":{"path":"/etc/config","content":"safe content"}}`), "")
	assert.True(t, d.Allow)

	// regex のみマッチ → スキップ → allow-all
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"write_file","arguments":{"path":"/home/user/config","content":"password = secret"}}`), "")
	assert.True(t, d.Allow)
}

func TestValidateArgumentPatternsRegex(t *testing.T) {
	// 不正な正規表現 → エラー
	_, err := Parse([]byte(`
version: v1
mode: enforce
rules:
  - name: bad-regex
    match:
      methods: ["tools/call"]
      argument_patterns:
        query: ["[invalid"]
    action: deny
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex")
}

func TestExtractArgumentsNested(t *testing.T) {
	params := json.RawMessage(`{"name":"tool","arguments":{"path":"/home","options":{"recursive":true,"depth":3}}}`)
	args := extractArguments(params)

	// top-level キーも保持
	assert.Equal(t, "/home", args["path"])
	assert.Contains(t, args["options"], `"recursive"`)

	// ドット記法で展開
	assert.Equal(t, "true", args["options.recursive"])
	assert.Equal(t, "3", args["options.depth"])
}

func TestExtractArgumentsDeepNested(t *testing.T) {
	params := json.RawMessage(`{"name":"tool","arguments":{"a":{"b":{"c":{"d":{"e":"deep"}}}}}}`)
	args := extractArguments(params)

	assert.Equal(t, "deep", args["a.b.c.d.e"]) // depth 4 — 制限内
}

func TestExtractArgumentsMaxDepth(t *testing.T) {
	// depth 5 以上は展開されない
	// a(1) → b(2) → c(3) → d(4) → e(5=maxNestDepth で停止) → f は展開されない
	params := json.RawMessage(`{"name":"tool","arguments":{"a":{"b":{"c":{"d":{"e":{"f":"too-deep"}}}}}}}`)
	args := extractArguments(params)

	// a.b.c.d まで（depth 4）は展開される
	assert.NotEmpty(t, args["a.b.c.d"])
	// a.b.c.d.e は depth=5 で停止するため、オブジェクトの JSON 文字列のまま
	assert.Contains(t, args["a.b.c.d.e"], "too-deep")
	// a.b.c.d.e.f は展開されない（depth >= maxNestDepth）
	_, exists := args["a.b.c.d.e.f"]
	assert.False(t, exists)
}

func TestEngineNestedArgumentMatch(t *testing.T) {
	engine := newTestPolicy([]Rule{
		{Name: "block-recursive-delete", Match: Match{
			Methods:   []string{"tools/call"},
			Tools:     []string{"file_op"},
			Arguments: map[string][]string{
				"action":            {"delete"},
				"options.recursive": {"true"},
			},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	})

	// ネストされた引数がマッチ → ブロック
	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"file_op","arguments":{"action":"delete","options":{"recursive":true}}}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "block-recursive-delete", d.RuleName)

	// recursive=false → マッチしない → 許可
	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"file_op","arguments":{"action":"delete","options":{"recursive":false}}}`), "")
	assert.True(t, d.Allow)
}

func TestValidateArgumentPatternsRequiresToolsCall(t *testing.T) {
	_, err := Parse([]byte(`
version: v1
mode: enforce
rules:
  - name: bad-rule
    match:
      methods: ["tools/list"]
      argument_patterns:
        query: [".*"]
    action: deny
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "argument_patterns requires methods to include \"tools/call\"")
}

func TestValidateRuleMode(t *testing.T) {
	// 不正な mode → エラー
	_, err := Parse([]byte(`
version: v1
mode: enforce
rules:
  - name: bad-mode
    match:
      methods: ["*"]
    action: deny
    mode: invalid
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mode")
}

func TestIsPathLike(t *testing.T) {
	assert.True(t, isPathLike("/etc/passwd"))
	assert.True(t, isPathLike("/home/user/file.txt"))
	assert.True(t, isPathLike("../etc/passwd"))
	assert.True(t, isPathLike("foo/../bar"))
	assert.False(t, isPathLike("hello"))
	assert.False(t, isPathLike("*.env"))
	assert.False(t, isPathLike(""))
}

func TestLoadAndEvaluate(t *testing.T) {
	pf, err := Load("../../testdata/policy_deny_tools.yaml")
	require.NoError(t, err)

	engine := NewEngine(pf)

	d := engine.Evaluate("tools/call", json.RawMessage(`{"name":"exec_cmd"}`), "")
	assert.False(t, d.Allow)
	assert.Equal(t, "deny-exec", d.RuleName)

	d = engine.Evaluate("tools/call", json.RawMessage(`{"name":"read_file"}`), "")
	assert.True(t, d.Allow)
}
