package cmd

import (
	"fmt"
	"os"

	"github.com/knorq-ai/mcpgw/internal/policy"
	"github.com/spf13/cobra"
)

var policyDiffCmd = &cobra.Command{
	Use:   "diff <old.yaml> <new.yaml>",
	Short: "2つのポリシーファイルの差分を表示する",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldPF, err := policy.Load(args[0])
		if err != nil {
			return fmt.Errorf("old policy: %w", err)
		}
		newPF, err := policy.Load(args[1])
		if err != nil {
			return fmt.Errorf("new policy: %w", err)
		}

		result := policy.Diff(oldPF, newPF)
		if !result.HasDiff() {
			fmt.Println("差分なし")
			return nil
		}

		fmt.Print(result.String())
		fmt.Println()
		fmt.Println(result.Summary())

		// 差分がある場合は終了コード 1 を返す（CI 向け）
		os.Exit(1)
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyDiffCmd)
}
