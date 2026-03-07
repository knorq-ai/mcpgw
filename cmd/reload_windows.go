//go:build windows

package cmd

import (
	"context"

	"github.com/yuyamorita/mcpgw/internal/intercept"
)

// watchPolicyReload は Windows では no-op。SIGHUP が存在しないため。
func watchPolicyReload(_ context.Context, _ string, _ *intercept.PolicyInterceptor) {}
