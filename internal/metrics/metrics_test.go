package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	// テスト用レジストリで登録確認
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(RequestsTotal))
	require.NoError(t, reg.Register(RequestDuration))
	require.NoError(t, reg.Register(ActiveSessions))
	require.NoError(t, reg.Register(UpstreamErrors))

	// メトリクスが記録できることを確認
	RequestsTotal.WithLabelValues("initialize", "pass").Inc()
	RequestDuration.WithLabelValues("POST").Observe(0.1)
	ActiveSessions.Inc()
	UpstreamErrors.Inc()

	mfs, err := reg.Gather()
	require.NoError(t, err)
	assert.True(t, len(mfs) > 0, "メトリクスが記録されるべき")

	// メトリクス名を確認
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	assert.True(t, names["mcpgw_requests_total"])
	assert.True(t, names["mcpgw_request_duration_seconds"])
	assert.True(t, names["mcpgw_active_sessions"])
	assert.True(t, names["mcpgw_upstream_errors_total"])
}
