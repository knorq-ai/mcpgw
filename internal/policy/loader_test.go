package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseValidPolicy(t *testing.T) {
	yaml := `
version: v1
mode: enforce
rules:
  - name: deny-exec
    match:
      methods: ["tools/call"]
      tools: ["exec_*"]
    action: deny
  - name: default-allow
    match:
      methods: ["*"]
    action: allow
`
	pf, err := Parse([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "v1", pf.Version)
	assert.Equal(t, "enforce", pf.Mode)
	require.Len(t, pf.Rules, 2)
	assert.Equal(t, "deny-exec", pf.Rules[0].Name)
	assert.Equal(t, []string{"tools/call"}, pf.Rules[0].Match.Methods)
	assert.Equal(t, []string{"exec_*"}, pf.Rules[0].Match.Tools)
	assert.Equal(t, "deny", pf.Rules[0].Action)
}

func TestParseAuditMode(t *testing.T) {
	yaml := `
version: v1
mode: audit
rules:
  - name: default-allow
    match:
      methods: ["*"]
    action: allow
`
	pf, err := Parse([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "audit", pf.Mode)
}

func TestParseInvalidVersion(t *testing.T) {
	yaml := `
version: v2
mode: enforce
rules:
  - name: test
    match:
      methods: ["*"]
    action: allow
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestParseInvalidMode(t *testing.T) {
	yaml := `
version: v1
mode: invalid
rules:
  - name: test
    match:
      methods: ["*"]
    action: allow
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mode")
}

func TestParseNoRules(t *testing.T) {
	yaml := `
version: v1
mode: enforce
rules: []
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rules")
}

func TestParseInvalidAction(t *testing.T) {
	yaml := `
version: v1
mode: enforce
rules:
  - name: test
    match:
      methods: ["*"]
    action: maybe
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported action")
}

func TestParseNoMethods(t *testing.T) {
	yaml := `
version: v1
mode: enforce
rules:
  - name: test
    match: {}
    action: allow
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one method")
}

func TestParseNoName(t *testing.T) {
	yaml := `
version: v1
mode: enforce
rules:
  - match:
      methods: ["*"]
    action: allow
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestLoadFromFile(t *testing.T) {
	pf, err := Load("../../testdata/policy_allow_all.yaml")
	require.NoError(t, err)
	assert.Equal(t, "v1", pf.Version)
	assert.Len(t, pf.Rules, 1)
}

func TestLoadFromDenyFile(t *testing.T) {
	pf, err := Load("../../testdata/policy_deny_tools.yaml")
	require.NoError(t, err)
	assert.Len(t, pf.Rules, 2)
	assert.Equal(t, "deny", pf.Rules[0].Action)
}

func TestLoadNonexistent(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	require.Error(t, err)
}

func TestLoadInvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(":::invalid"), 0o600))
	_, err := Load(path)
	require.Error(t, err)
}
