package main

import (
	"os"

	"github.com/yuyamorita/mcpgw/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
