package policy

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
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
	policy             *PolicyFile
	compiledArgPatterns []map[string][]*regexp.Regexp // ルールごとの argument_patterns コンパイル済み正規表現
	compiledRespPatterns []*regexp.Regexp             // response_patterns コンパイル済み正規表現
}

// NewEngine はポリシーファイルから Engine を構築する。
func NewEngine(pf *PolicyFile) *Engine {
	e := &Engine{policy: pf}

	// argument_patterns のプリコンパイル
	// loader.go でバリデーション済みのためコンパイル失敗は通常起こらないが、
	// 万一失敗した場合はそのパターンのみスキップする（fail-open）。
	e.compiledArgPatterns = make([]map[string][]*regexp.Regexp, len(pf.Rules))
	for i, rule := range pf.Rules {
		if len(rule.Match.ArgumentPatterns) > 0 {
			compiled := make(map[string][]*regexp.Regexp, len(rule.Match.ArgumentPatterns))
			for argName, patterns := range rule.Match.ArgumentPatterns {
				regexps := make([]*regexp.Regexp, 0, len(patterns))
				for _, p := range patterns {
					if re, err := regexp.Compile(p); err == nil {
						regexps = append(regexps, re)
					}
				}
				compiled[argName] = regexps
			}
			e.compiledArgPatterns[i] = compiled
		}
	}

	// response_patterns のプリコンパイル
	for _, p := range pf.ResponsePatterns {
		if re, err := regexp.Compile(p); err == nil {
			e.compiledRespPatterns = append(e.compiledRespPatterns, re)
		}
	}

	return e
}

// EvaluateInput はポリシー評価の入力パラメータ。
type EvaluateInput struct {
	Method  string
	Params  json.RawMessage
	Subject string
	Roles   []string
}

// Evaluate はメソッド名と生パラメータに対してポリシーを評価する。
// subject は認証済み Identity の Subject（未認証の場合は空文字列）。
// first-match-wins: 最初にマッチしたルールの action を返す。
// どのルールにもマッチしない場合は deny（暗黙の deny-all）。
func (e *Engine) Evaluate(method string, params json.RawMessage, subject string, roles ...[]string) Decision {
	var r []string
	if len(roles) > 0 {
		r = roles[0]
	}
	return e.EvaluateWithInput(EvaluateInput{
		Method:  method,
		Params:  params,
		Subject: subject,
		Roles:   r,
	})
}

// EvaluateWithInput は EvaluateInput に基づいてポリシーを評価する。
func (e *Engine) EvaluateWithInput(input EvaluateInput) Decision {
	// extractArguments / ExtractToolName の結果をキャッシュ
	var argsCache map[string]string
	argsCached := false
	var toolNameCache string
	toolNameCached := false

	for i, rule := range e.policy.Rules {
		if !matchMethods(rule.Match.Methods, input.Method) {
			continue
		}
		if len(rule.Match.Tools) > 0 && input.Method == MethodToolsCall {
			if !toolNameCached {
				toolNameCache = ExtractToolName(input.Params)
				toolNameCached = true
			}
			if !matchTools(rule.Match.Tools, toolNameCache) {
				continue
			}
		}
		if (len(rule.Match.Arguments) > 0 || len(rule.Match.ArgumentPatterns) > 0) && input.Method == MethodToolsCall {
			if !argsCached {
				argsCache = extractArguments(input.Params)
				argsCached = true
			}
			if len(rule.Match.Arguments) > 0 && !matchArguments(rule.Match.Arguments, argsCache) {
				continue
			}
			if len(rule.Match.ArgumentPatterns) > 0 && !matchArgumentPatterns(e.compiledArgPatterns[i], argsCache) {
				continue
			}
		}
		if len(rule.Match.Subjects) > 0 {
			if !matchSubjects(rule.Match.Subjects, input.Subject) {
				continue
			}
		}
		if len(rule.Match.Roles) > 0 {
			if !matchRoles(rule.Match.Roles, input.Roles) {
				continue
			}
		}
		mode := rule.Mode
		if mode == "" {
			mode = e.policy.Mode
		}
		return Decision{
			Allow:    rule.Action == "allow",
			RuleName: rule.Name,
			Mode:     mode,
		}
	}
	// 暗黙の deny-all
	return Decision{Allow: false, RuleName: "(implicit-deny)", Mode: e.policy.Mode}
}

// matchRoles はロールリストがパターンのいずれかにマッチするか判定する。
// ロールが空（未認証またはロールなし）の場合は常に false を返す（fail-closed）。
func matchRoles(patterns []string, roles []string) bool {
	if len(roles) == 0 {
		return false
	}
	for _, role := range roles {
		for _, p := range patterns {
			if globMatch(p, role) {
				return true
			}
		}
	}
	return false
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

// Policy はポリシーファイルを返す。
func (e *Engine) Policy() *PolicyFile {
	return e.policy
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

// stringifyJSONValue は JSON 値を文字列に変換する。
// 文字列型は引用符を除去し、数値・bool はそのまま文字列化する。
func stringifyJSONValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// null はそのまま空文字列
	if string(raw) == "null" {
		return ""
	}
	// 文字列型を試行
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// 数値型を試行
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		// 整数の場合は小数点なし
		if f == float64(int64(f)) {
			return strconv.FormatInt(int64(f), 10)
		}
		return fmt.Sprintf("%g", f)
	}
	// bool 型を試行
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return strconv.FormatBool(b)
	}
	// その他（配列・オブジェクト等）は JSON 文字列をそのまま返す
	return string(raw)
}

// maxNestDepth はネスト展開の最大深度。
const maxNestDepth = 5

// extractArguments は tools/call の params.arguments を抽出し、各値を文字列化する。
// ネストされたオブジェクトはドット記法でフラット化する（例: options.recursive）。
// top-level キーも保持し後方互換を維持する。
func extractArguments(params json.RawMessage) map[string]string {
	if len(params) == 0 {
		return nil
	}
	var p struct {
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil
	}
	if len(p.Arguments) == 0 {
		return nil
	}
	result := make(map[string]string, len(p.Arguments))
	for k, v := range p.Arguments {
		result[k] = stringifyJSONValue(v)
		flattenNested(k, v, result, 1)
	}
	return result
}

// flattenNested はネストされた JSON オブジェクトをドット記法でフラット化する。
func flattenNested(prefix string, raw json.RawMessage, result map[string]string, depth int) {
	if depth >= maxNestDepth || len(raw) == 0 {
		return
	}
	// JSON オブジェクト以外は Unmarshal せずに早期リターン
	if raw[0] != '{' {
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return
	}
	for k, v := range obj {
		key := prefix + "." + k
		result[key] = stringifyJSONValue(v)
		flattenNested(key, v, result, depth+1)
	}
}

// matchArguments はポリシーの引数パターンが実引数にマッチするか判定する。
// 全指定引数がマッチ → AND、各パターンリスト内 → OR。
// 引数が存在しない場合は不一致（fail-closed）。
// パス風の値は path.Clean で正規化してからマッチする（パストラバーサル防止）。
func matchArguments(patterns map[string][]string, args map[string]string) bool {
	for argName, globs := range patterns {
		val, ok := args[argName]
		if !ok {
			return false // 引数が存在しない → fail-closed
		}
		// パス風の値を正規化してパストラバーサルを防止
		// バックスラッシュをスラッシュに統一してから正規化する
		if isPathLike(val) {
			val = path.Clean(strings.ReplaceAll(val, `\`, "/"))
		}
		matched := false
		for _, g := range globs {
			if globMatch(g, val) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// isPathLike は値がパス風文字列かどうかを判定する。
// "/" や "\" で始まるか、".." を含む場合にパス風とみなす。
// Windows スタイルのバックスラッシュパスも検出する。
func isPathLike(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\`) || strings.Contains(s, "..")
}

// matchArgumentPatterns はコンパイル済み正規表現で引数値をマッチングする。
// 全指定引数がマッチ → AND、各パターンリスト内 → OR。
func matchArgumentPatterns(compiled map[string][]*regexp.Regexp, args map[string]string) bool {
	if compiled == nil {
		return false
	}
	for argName, regexps := range compiled {
		val, ok := args[argName]
		if !ok {
			return false // 引数が存在しない → fail-closed
		}
		matched := false
		for _, re := range regexps {
			if re.MatchString(val) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// ResponsePatterns はコンパイル済みレスポンスパターンを返す。
func (e *Engine) ResponsePatterns() []*regexp.Regexp {
	return e.compiledRespPatterns
}

// AllowedTools は許可ツールリストを返す。
func (e *Engine) AllowedTools() []string {
	return e.policy.AllowedTools
}

// GlobMatch は公開用の glob マッチ関数。
func GlobMatch(pattern, s string) bool {
	return globMatch(pattern, s)
}

// ExtractToolName は tools/call の params から name フィールドを抽出する。
func ExtractToolName(params json.RawMessage) string {
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
