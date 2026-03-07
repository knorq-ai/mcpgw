package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/knorq-ai/mcpgw/internal/policy"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "ポリシー関連のサブコマンド",
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "ポリシー YAML を検証する",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pf, err := policy.Load(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("OK: %d rules, mode=%s\n", len(pf.Rules), pf.Mode)
		for i, r := range pf.Rules {
			fmt.Printf("  [%d] %s: %s (methods=%v", i, r.Name, r.Action, r.Match.Methods)
			if len(r.Match.Tools) > 0 {
				fmt.Printf(", tools=%v", r.Match.Tools)
			}
			fmt.Println(")")
		}
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyValidateCmd)
	rootCmd.AddCommand(policyCmd)
}
