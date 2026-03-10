package servereval

import "github.com/knorq-ai/mcpgw/internal/policy"

// リスクレベルの定義。
const (
	RiskHigh   = "high"
	RiskMedium = "medium"
	RiskLow    = "low"
)

// 高リスクツール名パターン。
var highRiskPatterns = []string{
	"exec_*", "run_*", "send_*", "delete_*", "write_*", "sql_*",
}

// 中リスクツール名パターン。
var mediumRiskPatterns = []string{
	"read_file", "get_env", "list_env", "list_*",
}

// ScoreTool はツール名からリスクレベルを判定する。
func ScoreTool(name string) string {
	for _, pat := range highRiskPatterns {
		if policy.GlobMatch(pat, name) {
			return RiskHigh
		}
	}
	for _, pat := range mediumRiskPatterns {
		if policy.GlobMatch(pat, name) {
			return RiskMedium
		}
	}
	return RiskLow
}

// ScoreTools はツールリストからリスクレベルとスコアを算出する。
// 最高リスクのツールが全体のリスクレベルを決定し、スコアは平均値。
func ScoreTools(tools []ToolInfo) (riskLevel string, riskScore float64) {
	if len(tools) == 0 {
		return RiskLow, 0.0
	}

	var total float64
	maxLevel := RiskLow

	for _, t := range tools {
		level := t.RiskLevel
		if level == "" {
			level = ScoreTool(t.Name)
		}
		score := levelToScore(level)
		total += score
		if riskOrder(level) > riskOrder(maxLevel) {
			maxLevel = level
		}
	}

	return maxLevel, total / float64(len(tools))
}

func levelToScore(level string) float64 {
	switch level {
	case RiskHigh:
		return 0.9
	case RiskMedium:
		return 0.5
	default:
		return 0.2
	}
}

func riskOrder(level string) int {
	switch level {
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	default:
		return 1
	}
}
