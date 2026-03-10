package cmd

import (
	"testing"
)

func TestResolveMgmtAddr(t *testing.T) {
	tests := []struct {
		name          string
		addr          string
		allowExternal bool
		want          string
	}{
		{
			name:          "空ホストで AllowExternal=false → 127.0.0.1",
			addr:          ":9091",
			allowExternal: false,
			want:          "127.0.0.1:9091",
		},
		{
			name:          "0.0.0.0 で AllowExternal=false → 127.0.0.1",
			addr:          "0.0.0.0:9091",
			allowExternal: false,
			want:          "127.0.0.1:9091",
		},
		{
			name:          "[::] で AllowExternal=false → 127.0.0.1",
			addr:          "[::]:9091",
			allowExternal: false,
			want:          "127.0.0.1:9091",
		},
		{
			name:          "空ホストで AllowExternal=true → そのまま",
			addr:          ":9091",
			allowExternal: true,
			want:          ":9091",
		},
		{
			name:          "明示的ホスト → そのまま",
			addr:          "10.0.0.1:9091",
			allowExternal: false,
			want:          "10.0.0.1:9091",
		},
		{
			name:          "127.0.0.1 → そのまま",
			addr:          "127.0.0.1:9091",
			allowExternal: false,
			want:          "127.0.0.1:9091",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveMgmtAddr(tt.addr, tt.allowExternal)
			if got != tt.want {
				t.Errorf("resolveMgmtAddr(%q, %v) = %q, want %q", tt.addr, tt.allowExternal, got, tt.want)
			}
		})
	}
}
