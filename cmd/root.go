package cmd

import (
	"github.com/spf13/cobra"
)

var configPath string

var rootCmd = &cobra.Command{
	Use:   "mcpgw",
	Short: "MCP Security Gateway",
	Long:  "MCP Security Gateway — クライアントと MCP サーバー間の通信を監査・制御するセキュリティプロキシ。",
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "設定ファイルのパス (env: MCPGW_CONFIG)")
}

func Execute() error {
	return rootCmd.Execute()
}
