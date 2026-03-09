package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffNoDifference(t *testing.T) {
	pf := &PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []Rule{
			{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
		},
	}
	result := Diff(pf, pf)
	assert.False(t, result.HasDiff())
	assert.Equal(t, "差分なし", result.String())
	assert.Equal(t, "差分なし", result.Summary())
}

func TestDiffModeChanged(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "audit", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())
	assert.Len(t, result.Entries, 1)
	assert.Equal(t, DiffChanged, result.Entries[0].Type)
	assert.Equal(t, "mode", result.Entries[0].Section)
	assert.Equal(t, "enforce", result.Entries[0].Old)
	assert.Equal(t, "audit", result.Entries[0].New)
}

func TestDiffRuleAdded(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())

	var added []DiffEntry
	for _, e := range result.Entries {
		if e.Type == DiffAdded && e.Section == "rule" {
			added = append(added, e)
		}
	}
	require.Len(t, added, 1)
	assert.Equal(t, "deny-exec", added[0].Name)
	assert.Contains(t, added[0].New, "action=deny")
}

func TestDiffRuleRemoved(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())

	var removed []DiffEntry
	for _, e := range result.Entries {
		if e.Type == DiffRemoved && e.Section == "rule" {
			removed = append(removed, e)
		}
	}
	require.Len(t, removed, 1)
	assert.Equal(t, "deny-exec", removed[0].Name)
}

func TestDiffRuleChanged(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "allow"}, // action 変更
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())

	var changed []DiffEntry
	for _, e := range result.Entries {
		if e.Type == DiffChanged && e.Section == "rule" {
			changed = append(changed, e)
		}
	}
	require.Len(t, changed, 1)
	assert.Equal(t, "deny-exec", changed[0].Name)
	assert.Contains(t, changed[0].Old, "action=deny")
	assert.Contains(t, changed[0].New, "action=allow")
}

func TestDiffRuleToolsChanged(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*", "run_*"}}, Action: "deny"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())
	assert.Equal(t, DiffChanged, result.Entries[0].Type)
	assert.Equal(t, "rule", result.Entries[0].Section)
}

func TestDiffRuleModeChanged(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}}, Action: "deny"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}}, Action: "deny", Mode: "audit"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())
	assert.Equal(t, DiffChanged, result.Entries[0].Type)
	assert.Equal(t, "rule", result.Entries[0].Section)
}

func TestDiffResponsePatternsAdded(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}, ResponsePatterns: []string{`(?i)api[_-]?key`}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())

	var added []DiffEntry
	for _, e := range result.Entries {
		if e.Section == "response_patterns" {
			added = append(added, e)
		}
	}
	require.Len(t, added, 1)
	assert.Equal(t, DiffAdded, added[0].Type)
	assert.Equal(t, `(?i)api[_-]?key`, added[0].Name)
}

func TestDiffResponsePatternsRemoved(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}, ResponsePatterns: []string{`(?i)secret`, `(?i)password`}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}, ResponsePatterns: []string{`(?i)password`}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())

	var removed []DiffEntry
	for _, e := range result.Entries {
		if e.Section == "response_patterns" && e.Type == DiffRemoved {
			removed = append(removed, e)
		}
	}
	require.Len(t, removed, 1)
	assert.Equal(t, `(?i)secret`, removed[0].Name)
}

func TestDiffAllowedToolsChanged(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}, AllowedTools: []string{"read_*"}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}, AllowedTools: []string{"read_*", "write_*"}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())

	var added []DiffEntry
	for _, e := range result.Entries {
		if e.Section == "allowed_tools" && e.Type == DiffAdded {
			added = append(added, e)
		}
	}
	require.Len(t, added, 1)
	assert.Equal(t, "write_*", added[0].Name)
}

func TestDiffMultipleChanges(t *testing.T) {
	old := &PolicyFile{
		Version: "v1",
		Mode:    "enforce",
		Rules: []Rule{
			{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*"}}, Action: "deny"},
			{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
		},
		ResponsePatterns: []string{`(?i)secret`},
		AllowedTools:     []string{"read_*"},
	}
	new := &PolicyFile{
		Version: "v1",
		Mode:    "audit",
		Rules: []Rule{
			{Name: "deny-exec", Match: Match{Methods: []string{"tools/call"}, Tools: []string{"exec_*", "run_*"}}, Action: "deny"},
			{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
			{Name: "new-rule", Match: Match{Methods: []string{"tools/call"}}, Action: "deny"},
		},
		ResponsePatterns: []string{`(?i)secret`, `(?i)password`},
		AllowedTools:     []string{"read_*", "write_*"},
	}

	result := Diff(old, new)
	require.True(t, result.HasDiff())

	// mode 変更、rule 変更(deny-exec)、rule 追加(new-rule)、
	// response_patterns 追加、allowed_tools 追加 = 5 件
	assert.Len(t, result.Entries, 5)

	summary := result.Summary()
	assert.Contains(t, summary, "5 件の差分")
}

func TestDiffRuleSubjectsChanged(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"tools/call"}, Subjects: []string{"admin-*"}}, Action: "allow"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{Methods: []string{"tools/call"}, Subjects: []string{"admin-*", "ops-*"}}, Action: "allow"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())
	assert.Equal(t, DiffChanged, result.Entries[0].Type)
	assert.Equal(t, "rule", result.Entries[0].Section)
}

func TestDiffRuleArgumentsChanged(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{
			Methods:   []string{"tools/call"},
			Arguments: map[string][]string{"path": {"/etc/*"}},
		}, Action: "deny"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{
			Methods:   []string{"tools/call"},
			Arguments: map[string][]string{"path": {"/etc/*", "/var/*"}},
		}, Action: "deny"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())
	assert.Equal(t, "rule", result.Entries[0].Section)
	assert.Equal(t, DiffChanged, result.Entries[0].Type)
}

func TestDiffRuleArgumentPatternsChanged(t *testing.T) {
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{
			Methods:          []string{"tools/call"},
			ArgumentPatterns: map[string][]string{"query": {`(?i)DROP`}},
		}, Action: "deny"},
	}}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: []Rule{
		{Name: "r1", Match: Match{
			Methods:          []string{"tools/call"},
			ArgumentPatterns: map[string][]string{"query": {`(?i)DROP`, `(?i)DELETE`}},
		}, Action: "deny"},
	}}

	result := Diff(old, new)
	require.True(t, result.HasDiff())
	assert.Equal(t, DiffChanged, result.Entries[0].Type)
}

func TestStringSliceEqual(t *testing.T) {
	assert.True(t, stringSliceEqual(nil, nil))
	assert.True(t, stringSliceEqual([]string{}, []string{}))
	assert.True(t, stringSliceEqual([]string{"a", "b"}, []string{"a", "b"}))
	assert.False(t, stringSliceEqual([]string{"a"}, []string{"a", "b"}))
	assert.False(t, stringSliceEqual([]string{"a", "b"}, []string{"b", "a"}))
	assert.False(t, stringSliceEqual(nil, []string{"a"}))
}

func TestStringMapSliceEqual(t *testing.T) {
	assert.True(t, stringMapSliceEqual(nil, nil))
	assert.True(t, stringMapSliceEqual(
		map[string][]string{"a": {"1", "2"}},
		map[string][]string{"a": {"1", "2"}},
	))
	assert.False(t, stringMapSliceEqual(
		map[string][]string{"a": {"1"}},
		map[string][]string{"a": {"1", "2"}},
	))
	assert.False(t, stringMapSliceEqual(
		map[string][]string{"a": {"1"}},
		map[string][]string{"b": {"1"}},
	))
}

func TestFormatRule(t *testing.T) {
	r := Rule{
		Name:   "test",
		Action: "deny",
		Mode:   "audit",
		Match: Match{
			Methods:  []string{"tools/call"},
			Tools:    []string{"exec_*"},
			Subjects: []string{"admin-*"},
		},
	}
	s := formatRule(r)
	assert.Contains(t, s, "action=deny")
	assert.Contains(t, s, "mode=audit")
	assert.Contains(t, s, "methods=")
	assert.Contains(t, s, "tools=")
	assert.Contains(t, s, "subjects=")
}

func TestDiffResultString(t *testing.T) {
	result := &DiffResult{
		Entries: []DiffEntry{
			{Type: DiffAdded, Section: "rule", Name: "new-rule", New: "action=deny"},
			{Type: DiffRemoved, Section: "rule", Name: "old-rule", Old: "action=allow"},
			{Type: DiffChanged, Section: "mode", Name: "mode", Old: "enforce", New: "audit"},
		},
	}
	s := result.String()
	assert.Contains(t, s, "+ [rule] new-rule")
	assert.Contains(t, s, "- [rule] old-rule")
	assert.Contains(t, s, "~ [mode] mode")
}

func TestDiffIdenticalRulesNoDiff(t *testing.T) {
	rules := []Rule{
		{Name: "deny-exec", Match: Match{
			Methods: []string{"tools/call"},
			Tools:   []string{"exec_*"},
		}, Action: "deny"},
		{Name: "allow-all", Match: Match{Methods: []string{"*"}}, Action: "allow"},
	}
	old := &PolicyFile{Version: "v1", Mode: "enforce", Rules: rules}
	new := &PolicyFile{Version: "v1", Mode: "enforce", Rules: rules}

	result := Diff(old, new)
	assert.False(t, result.HasDiff())
}
