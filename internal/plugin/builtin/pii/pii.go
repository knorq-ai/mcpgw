// Package pii は PII (個人情報) 検出プラグインを提供する。
// C→S (ツール引数) および S→C (レスポンス) の両方向でスキャンを行う。
package pii

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

const (
	// ModeDetect は検出のみでメッセージを通過させるモード。
	ModeDetect = "detect"
	// ModeRedact は PII を [REDACTED:type] に置換してブロックするモード。
	ModeRedact = "redact"
)

// Plugin は PII 検出プラグイン。
type Plugin struct {
	mode         string
	patterns     []*Pattern
	excludeTools map[string]bool
}

// New は未初期化の PII プラグインを生成する。
func New() *Plugin {
	return &Plugin{}
}

// Name はプラグイン名を返す。
func (p *Plugin) Name() string { return "pii" }

// Init は設定に基づいてプラグインを初期化する。
// config キー:
//   - mode: "detect" (デフォルト) または "redact"
//   - patterns: 使用するパターン名のリスト (省略時は全パターン)
//   - exclude_tools: スキャン除外ツール名のリスト
func (p *Plugin) Init(config map[string]any) error {
	// モード設定
	p.mode = ModeDetect
	if v, ok := config["mode"]; ok {
		if s, ok := v.(string); ok {
			switch s {
			case ModeDetect, ModeRedact:
				p.mode = s
			default:
				return fmt.Errorf("pii: unknown mode %q", s)
			}
		}
	}

	// パターン選択
	p.patterns = allPatterns
	if v, ok := config["patterns"]; ok {
		names := toStringSlice(v)
		if len(names) > 0 {
			selected := make([]*Pattern, 0, len(names))
			for _, name := range names {
				pat, exists := patternsByName[name]
				if !exists {
					return fmt.Errorf("pii: unknown pattern %q", name)
				}
				selected = append(selected, pat)
			}
			p.patterns = selected
		}
	}

	// 除外ツール
	p.excludeTools = make(map[string]bool)
	if v, ok := config["exclude_tools"]; ok {
		for _, name := range toStringSlice(v) {
			p.excludeTools[name] = true
		}
	}

	return nil
}

// Close はリソースを解放する（PII プラグインは保持リソースなし）。
func (p *Plugin) Close() error { return nil }

// Intercept はメッセージ中の PII を検出する。
func (p *Plugin) Intercept(ctx context.Context, dir intercept.Direction, msg *jsonrpc.Message, raw []byte) intercept.Result {
	if msg == nil || len(raw) == 0 {
		return intercept.Result{Action: intercept.ActionPass}
	}

	// 除外ツールの確認 (C→S tools/call の場合)
	if dir == intercept.DirClientToServer && msg.Method == "tools/call" {
		toolName := extractToolName(msg.Params)
		if p.excludeTools[toolName] {
			return intercept.Result{Action: intercept.ActionPass}
		}
	}

	// スキャン対象テキストを抽出
	text := extractText(dir, msg, raw)
	if text == "" {
		return intercept.Result{Action: intercept.ActionPass}
	}

	// PII パターンマッチング
	var findings []finding
	for _, pat := range p.patterns {
		matches := pat.Re.FindAllString(text, -1)
		for _, m := range matches {
			if pat.Validate != nil && !pat.Validate(m) {
				continue
			}
			findings = append(findings, finding{
				PatternName: pat.Name,
				Match:       m,
				Severity:    pat.Severity,
			})
		}
	}

	if len(findings) == 0 {
		return intercept.Result{Action: intercept.ActionPass}
	}

	// 最大 severity をスコアとする
	maxSeverity := 0.0
	patternNames := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Severity > maxSeverity {
			maxSeverity = f.Severity
		}
		patternNames = append(patternNames, f.PatternName)
	}

	details := map[string]any{
		"pattern_count": len(findings),
		"patterns":      uniqueStrings(patternNames),
		"direction":     dir.String(),
	}

	switch p.mode {
	case ModeRedact:
		// redact モード: PII を [REDACTED:pattern_name] に置換して通過させる
		redactedBody := redactFindings(raw, findings)
		return intercept.Result{
			Action:        intercept.ActionRedact,
			Reason:        fmt.Sprintf("PII redacted: %s", strings.Join(uniqueStrings(patternNames), ", ")),
			RuleName:      "pii:" + strings.Join(uniqueStrings(patternNames), ","),
			ThreatType:    "pii_detected",
			ThreatScore:   maxSeverity,
			ThreatDetails: details,
			RedactedBody:  redactedBody,
		}

	default:
		// detect モード: ログに記録して通過
		slog.Warn("PII detected in message",
			"direction", dir.String(),
			"patterns", uniqueStrings(patternNames),
			"count", len(findings),
		)
		return intercept.Result{
			Action:        intercept.ActionPass,
			ThreatType:    "pii_detected",
			ThreatScore:   maxSeverity,
			ThreatDetails: details,
		}
	}
}

// finding は PII 検出結果の1件。
type finding struct {
	PatternName string
	Match       string
	Severity    float64
}

// redactFindings は raw メッセージ中の PII マッチ箇所を [REDACTED:pattern_name] に置換する。
// 同一マッチ文字列が複数回出現する場合はすべて置換する。
func redactFindings(raw []byte, findings []finding) []byte {
	body := string(raw)
	for _, f := range findings {
		placeholder := "[REDACTED:" + f.PatternName + "]"
		body = strings.ReplaceAll(body, f.Match, placeholder)
	}
	return []byte(body)
}

// extractText はメッセージからスキャン対象テキストを抽出する。
func extractText(dir intercept.Direction, msg *jsonrpc.Message, raw []byte) string {
	switch dir {
	case intercept.DirClientToServer:
		// tools/call の arguments を文字列化
		if msg.Method == "tools/call" && len(msg.Params) > 0 {
			var p struct {
				Arguments json.RawMessage `json:"arguments"`
			}
			if json.Unmarshal(msg.Params, &p) == nil && len(p.Arguments) > 0 {
				return string(p.Arguments)
			}
		}
		// それ以外は params 全体
		if len(msg.Params) > 0 {
			return string(msg.Params)
		}
	case intercept.DirServerToClient:
		// レスポンスの result を対象とする
		if len(msg.Result) > 0 {
			return string(msg.Result)
		}
	}
	// フォールバック: raw 全体
	return string(raw)
}

// extractToolName は tools/call の params からツール名を抽出する。
func extractToolName(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(params, &p) == nil {
		return p.Name
	}
	return ""
}

// toStringSlice は any 型の値を []string に変換する。
func toStringSlice(v any) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// uniqueStrings は文字列スライスから重複を除去する（順序保持）。
func uniqueStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
