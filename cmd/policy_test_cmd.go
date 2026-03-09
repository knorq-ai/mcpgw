package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/knorq-ai/mcpgw/internal/policy"
	"gopkg.in/yaml.v3"
)

// TestScenarioFile はシナリオ YAML のトップレベル構造。
type TestScenarioFile struct {
	Scenarios []TestScenario `yaml:"scenarios"`
}

// TestScenario は個々のテストシナリオ。
type TestScenario struct {
	Name    string   `yaml:"name"`
	Method  string   `yaml:"method"`
	Params  string   `yaml:"params"`         // JSON 文字列
	Subject string   `yaml:"subject"`
	Roles   []string `yaml:"roles,omitempty"` // ドキュメント用（評価には使用しない）
	Expect  string   `yaml:"expect"`          // "allow" or "deny"
}

var policyTestCmd = &cobra.Command{
	Use:   "test <policy.yaml> <scenarios.yaml>",
	Short: "ポリシーをシナリオファイルでテストする",
	Long:  "ポリシーファイルとシナリオ定義ファイルを読み込み、各シナリオを評価して pass/fail を報告する。",
	Args:  cobra.ExactArgs(2),
	RunE:  runPolicyTest,
}

func init() {
	policyCmd.AddCommand(policyTestCmd)
}

func runPolicyTest(cmd *cobra.Command, args []string) error {
	policyPath := args[0]
	scenarioPath := args[1]

	// ポリシー読み込み
	pf, err := policy.Load(policyPath)
	if err != nil {
		return fmt.Errorf("policy load: %w", err)
	}
	engine := policy.NewEngine(pf)

	// シナリオ読み込み
	scenarios, err := loadScenarios(scenarioPath)
	if err != nil {
		return fmt.Errorf("scenarios load: %w", err)
	}

	if len(scenarios) == 0 {
		return fmt.Errorf("シナリオが定義されていない: %s", scenarioPath)
	}

	// 各シナリオを評価
	passed, failed := 0, 0
	for i, sc := range scenarios {
		var params json.RawMessage
		if sc.Params != "" {
			params = json.RawMessage(sc.Params)
		}

		decision := engine.Evaluate(sc.Method, params, sc.Subject)

		expectAllow := sc.Expect == "allow"
		ok := decision.Allow == expectAllow

		status := "PASS"
		if !ok {
			status = "FAIL"
			failed++
		} else {
			passed++
		}

		actualStr := "deny"
		if decision.Allow {
			actualStr = "allow"
		}

		fmt.Printf("  [%d] %s %s: expect=%s actual=%s rule=%q\n",
			i+1, status, sc.Name, sc.Expect, actualStr, decision.RuleName)
	}

	fmt.Printf("\n結果: %d passed, %d failed, %d total\n", passed, failed, len(scenarios))

	if failed > 0 {
		os.Exit(1)
	}
	return nil
}

// loadScenarios はシナリオ YAML ファイルを読み込む。
func loadScenarios(path string) ([]TestScenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var sf TestScenarioFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// バリデーション
	for i, sc := range sf.Scenarios {
		if sc.Name == "" {
			return nil, fmt.Errorf("scenario[%d]: name は必須", i)
		}
		if sc.Method == "" {
			return nil, fmt.Errorf("scenario[%d] %q: method は必須", i, sc.Name)
		}
		if sc.Expect != "allow" && sc.Expect != "deny" {
			return nil, fmt.Errorf("scenario[%d] %q: expect は \"allow\" または \"deny\" である必要がある (got %q)", i, sc.Name, sc.Expect)
		}
		// params が指定されている場合、有効な JSON か検証する
		if sc.Params != "" {
			if !json.Valid([]byte(sc.Params)) {
				return nil, fmt.Errorf("scenario[%d] %q: params が不正な JSON: %s", i, sc.Name, sc.Params)
			}
		}
	}

	return sf.Scenarios, nil
}
