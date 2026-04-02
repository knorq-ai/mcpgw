package servereval

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScoreTool(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"exec_cmd", RiskHigh},
		{"run_script", RiskHigh},
		{"send_email", RiskHigh},
		{"delete_file", RiskHigh},
		{"write_data", RiskHigh},
		{"sql_query", RiskHigh},
		{"read_file", RiskMedium},
		{"get_env", RiskMedium},
		{"list_env", RiskMedium},
		{"list_files", RiskMedium},
		{"get_weather", RiskLow},
		{"search", RiskLow},
		{"echo", RiskLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ScoreTool(tt.name))
		})
	}
}

func TestScoreToolsEmpty(t *testing.T) {
	level, score := ScoreTools(nil)
	assert.Equal(t, RiskLow, level)
	assert.Equal(t, 0.0, score)
}

func TestScoreToolsAllLow(t *testing.T) {
	tools := []ToolInfo{
		{Name: "echo"},
		{Name: "get_weather"},
	}
	level, score := ScoreTools(tools)
	assert.Equal(t, RiskLow, level)
	assert.InDelta(t, 0.2, score, 0.01)
}

func TestScoreToolsMixed(t *testing.T) {
	tools := []ToolInfo{
		{Name: "echo"},       // low 0.2
		{Name: "exec_cmd"},   // high 0.9
		{Name: "list_files"}, // medium 0.5
	}
	level, score := ScoreTools(tools)
	assert.Equal(t, RiskHigh, level)
	// avg = (0.2 + 0.9 + 0.5) / 3 ≈ 0.533
	assert.InDelta(t, 0.533, score, 0.01)
}

func TestScoreToolsPreScored(t *testing.T) {
	tools := []ToolInfo{
		{Name: "custom", RiskLevel: RiskHigh},
	}
	level, score := ScoreTools(tools)
	assert.Equal(t, RiskHigh, level)
	assert.InDelta(t, 0.9, score, 0.01)
}
