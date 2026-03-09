// Package injection はプロンプトインジェクション検出プラグインを提供する。
// MCP メッセージに含まれるインジェクション試行をヒューリスティックに検出する。
package injection

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

// Plugin はプロンプトインジェクション検出プラグイン。
type Plugin struct {
	threshold   float64
	sensitivity string
	rules       []*rule
}

// New は未初期化の Plugin を生成する。
func New() *Plugin {
	return &Plugin{}
}

// Name はプラグイン名を返す。
func (p *Plugin) Name() string { return "injection" }

// Init は設定に基づいてプラグインを初期化する。
// config キー:
//   - threshold: ブロック閾値 (デフォルト: 0.7)
//   - sensitivity: 感度 ("low", "medium", "high", デフォルト: "medium")
func (p *Plugin) Init(config map[string]any) error {
	p.threshold = 0.7
	if v, ok := config["threshold"]; ok {
		switch val := v.(type) {
		case float64:
			p.threshold = val
		case int:
			p.threshold = float64(val)
		}
	}

	p.sensitivity = "medium"
	if v, ok := config["sensitivity"]; ok {
		if s, ok := v.(string); ok {
			switch s {
			case "low", "medium", "high":
				p.sensitivity = s
			default:
				return fmt.Errorf("injection: unknown sensitivity %q", s)
			}
		}
	}

	// 感度に応じてスコア倍率を適用
	p.rules = make([]*rule, len(defaultRules))
	multiplier := sensitivityMultiplier(p.sensitivity)
	for i, r := range defaultRules {
		p.rules[i] = &rule{
			Name:        r.Name,
			Re:          r.Re,
			Score:       r.Score * multiplier,
			Description: r.Description,
			Custom:      r.Custom,
		}
	}

	return nil
}

// Close はリソースを解放する。
func (p *Plugin) Close() error { return nil }

// Intercept はメッセージ中のプロンプトインジェクションを検出する。
// C→S 方向の全メソッドをスキャンする（S→C はスキップ）。
func (p *Plugin) Intercept(ctx context.Context, dir intercept.Direction, msg *jsonrpc.Message, raw []byte) intercept.Result {
	// S→C は通過
	if dir != intercept.DirClientToServer {
		return intercept.Result{Action: intercept.ActionPass}
	}

	if msg == nil || msg.Method == "" {
		return intercept.Result{Action: intercept.ActionPass}
	}

	// params 内の全文字列値を抽出
	text := extractArgText(msg.Params)
	if text == "" {
		return intercept.Result{Action: intercept.ActionPass}
	}

	// ルールを適用しスコアを累積
	totalScore := 0.0
	var matched []string
	details := make(map[string]any)

	for _, r := range p.rules {
		if r.matches(text) {
			totalScore += r.Score
			matched = append(matched, r.Name)
			details[r.Name] = r.Description
		}
	}

	if len(matched) == 0 {
		return intercept.Result{Action: intercept.ActionPass}
	}

	// スコアを 0-1 にクランプ
	if totalScore > 1.0 {
		totalScore = 1.0
	}

	threatDetails := map[string]any{
		"matched_rules": matched,
		"rules":         details,
		"score":         totalScore,
		"threshold":     p.threshold,
	}

	if totalScore >= p.threshold {
		return intercept.Result{
			Action:        intercept.ActionBlock,
			Reason:        fmt.Sprintf("prompt injection suspected (score=%.2f, threshold=%.2f): %s", totalScore, p.threshold, strings.Join(matched, ", ")),
			RuleName:      "injection:" + strings.Join(matched, ","),
			ThreatType:    "injection_suspected",
			ThreatScore:   totalScore,
			ThreatDetails: threatDetails,
		}
	}

	// 閾値未満でもログに記録
	slog.Warn("potential prompt injection detected (below threshold)",
		"score", totalScore,
		"threshold", p.threshold,
		"rules", matched,
	)
	return intercept.Result{
		Action:        intercept.ActionPass,
		ThreatType:    "injection_suspected",
		ThreatScore:   totalScore,
		ThreatDetails: threatDetails,
	}
}

// extractArgText は params JSON から全文字列値を再帰的に抽出し、
// JSON エスケープを解除したプレーンテキストとして返す。
// tools/call の arguments だけでなく、任意のメソッドの params を処理できる。
func extractArgText(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}

	var v any
	if err := json.Unmarshal(params, &v); err != nil {
		return ""
	}

	var strs []string
	collectStrings(v, &strs)
	return strings.Join(strs, "\n")
}

// collectStrings は任意の JSON 値を再帰的に走査し、文字列値をすべて収集する。
func collectStrings(v any, out *[]string) {
	switch val := v.(type) {
	case string:
		*out = append(*out, val)
	case map[string]any:
		for _, child := range val {
			collectStrings(child, out)
		}
	case []any:
		for _, child := range val {
			collectStrings(child, out)
		}
	}
}

// sensitivityMultiplier は感度に応じたスコア倍率を返す。
func sensitivityMultiplier(sensitivity string) float64 {
	switch sensitivity {
	case "low":
		return 0.7
	case "high":
		return 1.5
	default:
		return 1.0
	}
}
