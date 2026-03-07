package main

import (
	"os"

	"github.com/knorq-ai/mcpgw/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
