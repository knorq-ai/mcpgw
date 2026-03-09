package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadScenariosValid(t *testing.T) {
	scenarios, err := loadScenarios("../testdata/scenarios_rbac.yaml")
	require.NoError(t, err)
	require.Len(t, scenarios, 4)

	assert.Equal(t, "admin can exec", scenarios[0].Name)
	assert.Equal(t, "tools/call", scenarios[0].Method)
	assert.Equal(t, `{"name":"exec_cmd"}`, scenarios[0].Params)
	assert.Equal(t, "admin-alice", scenarios[0].Subject)
	assert.Equal(t, "allow", scenarios[0].Expect)

	assert.Equal(t, "user cannot exec", scenarios[1].Name)
	assert.Equal(t, "deny", scenarios[1].Expect)
}

func TestLoadScenariosFileNotFound(t *testing.T) {
	_, err := loadScenarios("nonexistent.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read")
}

func TestLoadScenariosInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(path, []byte(":::invalid"), 0644)

	_, err := loadScenarios(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestLoadScenariosEmptyName(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(path, []byte(`
scenarios:
  - name: ""
    method: "tools/call"
    expect: allow
`), 0644)

	_, err := loadScenarios(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name は必須")
}

func TestLoadScenariosEmptyMethod(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(path, []byte(`
scenarios:
  - name: "test"
    method: ""
    expect: allow
`), 0644)

	_, err := loadScenarios(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "method は必須")
}

func TestLoadScenariosInvalidExpect(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(path, []byte(`
scenarios:
  - name: "test"
    method: "tools/call"
    expect: "maybe"
`), 0644)

	_, err := loadScenarios(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expect は")
}

func TestLoadScenariosInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(path, []byte(`
scenarios:
  - name: "test"
    method: "tools/call"
    params: "not json"
    expect: allow
`), 0644)

	_, err := loadScenarios(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "不正な JSON")
}

func TestLoadScenariosEmptyParams(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "good.yaml")
	os.WriteFile(path, []byte(`
scenarios:
  - name: "test"
    method: "tools/list"
    expect: allow
`), 0644)

	scenarios, err := loadScenarios(path)
	require.NoError(t, err)
	require.Len(t, scenarios, 1)
	assert.Equal(t, "", scenarios[0].Params)
}

// TestRunPolicyTestAllPass はシナリオが全て pass するケースのテスト。
// runPolicyTest は os.Exit(1) を失敗時に呼ぶため、全 pass のケースのみ直接テストする。
func TestRunPolicyTestAllPass(t *testing.T) {
	// runPolicyTest を直接呼ぶ。成功時は os.Exit しないため安全。
	err := runPolicyTest(nil, []string{
		"../testdata/policy_rbac.yaml",
		"../testdata/scenarios_rbac.yaml",
	})
	assert.NoError(t, err)
}

func TestRunPolicyTestInvalidPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	scenPath := filepath.Join(tmpDir, "sc.yaml")
	os.WriteFile(scenPath, []byte(`
scenarios:
  - name: "test"
    method: "tools/list"
    expect: allow
`), 0644)

	err := runPolicyTest(nil, []string{"nonexistent.yaml", scenPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy load")
}

func TestRunPolicyTestInvalidScenario(t *testing.T) {
	err := runPolicyTest(nil, []string{
		"../testdata/policy_rbac.yaml",
		"nonexistent.yaml",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scenarios load")
}

func TestRunPolicyTestEmptyScenarios(t *testing.T) {
	tmpDir := t.TempDir()
	scenPath := filepath.Join(tmpDir, "empty.yaml")
	os.WriteFile(scenPath, []byte(`scenarios: []`), 0644)

	err := runPolicyTest(nil, []string{
		"../testdata/policy_rbac.yaml",
		scenPath,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "シナリオが定義されていない")
}
