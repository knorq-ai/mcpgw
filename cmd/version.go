package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ビルド時に -ldflags で注入
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "バージョンを表示する",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("mcpgw %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
