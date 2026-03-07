package policy

import (
	"encoding/json"
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

	assert.True(t, engine.IsAuditMode())

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
			assert.Equal(t, tt.want, extractToolName(tt.params))
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
