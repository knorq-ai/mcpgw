package policy

import (
	"encoding/json"
)

// MCP メソッド名定数。
const MethodToolsCall = "tools/call"

// Decision はエンジンの判定結果。
type Decision struct {
	Allow    bool
	RuleName string // マッチしたルール名
	Mode     string // "enforce" or "audit"
}

// Engine はポリシールールを評価する。
type Engine struct {
	policy *PolicyFile
}

// NewEngine はポリシーファイルから Engine を構築する。
func NewEngine(pf *PolicyFile) *Engine {
	return &Engine{policy: pf}
}

// Evaluate はメソッド名と生パラメータに対してポリシーを評価する。
// subject は認証済み Identity の Subject（未認証の場合は空文字列）。
// first-match-wins: 最初にマッチしたルールの action を返す。
// どのルールにもマッチしない場合は deny（暗黙の deny-all）。
func (e *Engine) Evaluate(method string, params json.RawMessage, subject string) Decision {
	for _, rule := range e.policy.Rules {
		if !matchMethods(rule.Match.Methods, method) {
			continue
		}
		if len(rule.Match.Tools) > 0 && method == MethodToolsCall {
			toolName := extractToolName(params)
			if !matchTools(rule.Match.Tools, toolName) {
				continue
			}
		}
		if len(rule.Match.Subjects) > 0 {
			if !matchSubjects(rule.Match.Subjects, subject) {
				continue
			}
		}
		return Decision{
			Allow:    rule.Action == "allow",
			RuleName: rule.Name,
			Mode:     e.policy.Mode,
		}
	}
	// 暗黙の deny-all
	return Decision{Allow: false, RuleName: "(implicit-deny)", Mode: e.policy.Mode}
}

// matchSubjects は subject が patterns のいずれかにマッチするか判定する。
// subject が空（未認証）の場合は常に false を返す（fail-closed）。
func matchSubjects(patterns []string, subject string) bool {
	if subject == "" {
		return false
	}
	for _, p := range patterns {
		if globMatch(p, subject) {
			return true
		}
	}
	return false
}

// IsAuditMode は audit モードかどうかを返す。
// audit モードでは deny 判定でもブロックせず、ログのみ。
func (e *Engine) IsAuditMode() bool {
	return e.policy.Mode == "audit"
}

// matchMethods はメソッド名がパターンリストのいずれかにマッチするか判定する。
func matchMethods(patterns []string, method string) bool {
	for _, p := range patterns {
		if globMatch(p, method) {
			return true
		}
	}
	return false
}

// matchTools はツール名がパターンリストのいずれかにマッチするか判定する。
func matchTools(patterns []string, toolName string) bool {
	if toolName == "" {
		return false
	}
	for _, p := range patterns {
		if globMatch(p, toolName) {
			return true
		}
	}
	return false
}

// maxGlobInput はマッチ対象文字列の最大長。
// 過度に長い入力によるCPU消費を防止する。
const maxGlobInput = 512

// globMatch はシンプルな glob マッチングを行う。
// filepath.Match と異なり、"*" は "/" を含む任意の文字列にマッチする。
// サポートするワイルドカード: "*"（任意の文字列）, "?"（任意の1文字）。
// O(n*m) の反復アルゴリズムでバックトラッキング爆発を回避する。
func globMatch(pattern, s string) bool {
	if len(s) > maxGlobInput {
		return false
	}

	px, sx := 0, 0       // pattern index, string index
	starPx, starSx := -1, -1 // 最後の '*' のパターン位置と文字列位置

	for sx < len(s) {
		if px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]) {
			px++
			sx++
		} else if px < len(pattern) && pattern[px] == '*' {
			starPx = px
			starSx = sx
			px++ // '*' をスキップ
		} else if starPx >= 0 {
			// バックトラック: '*' にもう1文字消費させる
			px = starPx + 1
			starSx++
			sx = starSx
		} else {
			return false
		}
	}

	// パターンの残りが全て '*' なら OK
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// extractToolName は tools/call の params から name フィールドを抽出する。
func extractToolName(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Name
}
