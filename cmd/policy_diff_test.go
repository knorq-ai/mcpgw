package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyDiffCmdNoDiff(t *testing.T) {
	// 同一ファイルの diff → 差分なし（os.Exit(1) されない）
	err := policyDiffCmd.RunE(nil, []string{
		"../testdata/policy_deny_tools.yaml",
		"../testdata/policy_deny_tools.yaml",
	})
	assert.NoError(t, err)
}

func TestPolicyDiffCmdInvalidOld(t *testing.T) {
	err := policyDiffCmd.RunE(nil, []string{
		"nonexistent.yaml",
		"../testdata/policy_deny_tools.yaml",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "old policy")
}

func TestPolicyDiffCmdInvalidNew(t *testing.T) {
	err := policyDiffCmd.RunE(nil, []string{
		"../testdata/policy_deny_tools.yaml",
		"nonexistent.yaml",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "new policy")
}
