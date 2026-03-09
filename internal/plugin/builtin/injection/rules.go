package injection

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
)

// rule はプロンプトインジェクション検出ルール。
type rule struct {
	Name        string
	Re          *regexp.Regexp // 検出用正規表現（nil の場合は Custom を使用）
	Score       float64        // 加算スコア (0.0-1.0)
	Description string
	// Custom は正規表現の代わりにカスタムロジックで検出するルール用。
	// nil の場合は Re によるマッチを使用する。
	Custom func(text string) bool
}

// matches はルールのマッチ判定を行う。
// Custom が設定されていればそちらを優先し、なければ Re によるマッチを行う。
func (r *rule) matches(text string) bool {
	if r.Custom != nil {
		return r.Custom(text)
	}
	if r.Re != nil {
		return r.Re.MatchString(text)
	}
	return false
}

// defaultRules は組み込みの検出ルール。
var defaultRules = []*rule{
	{
		Name:        "ignore_instructions",
		Re:          regexp.MustCompile(`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|context)`),
		Score:       0.5,
		Description: "指示の無視を要求するパターン",
	},
	{
		Name:        "new_instructions",
		Re:          regexp.MustCompile(`(?i)(new\s+instructions|system\s*prompt\s*[:=]|you\s+are\s+now|from\s+now\s+on|override\s+(all\s+)?instructions|begin\s+new\s+(session|conversation)|enter\s+(developer|admin|debug)\s+mode)`),
		Score:       0.5,
		Description: "新しい指示の注入パターン",
	},
	{
		Name:        "role_manipulation",
		Re:          regexp.MustCompile(`(?i)(act\s+as|pretend\s+(you\s+are|to\s+be|that\s+you)|you\s+are\s+a\s+(new|different)?|assume\s+the\s+role|roleplay\s+as|switch\s+(to|into)\s+(a\s+|the\s+)?(role|mode|persona)|from\s+now\s+on\s+you\s+are)`),
		Score:       0.3,
		Description: "ロール操作パターン",
	},
	{
		Name:        "delimiter_injection",
		Re:          regexp.MustCompile(`(?:^|\n)\s*(?:#{3,}|-{3,}|<{3,}|>{3,}|={3,}|\*{3,})\s*\n?\s*(?i)(?:system|instruction|prompt|admin|override|command|new\s+task)`),
		Score:       0.4,
		Description: "区切り文字によるインジェクションパターン",
	},
	{
		Name:        "base64_injection",
		Score:       0.4,
		Description: "Base64 エンコードされた命令の検出",
		Custom:      detectBase64Injection,
	},
	{
		Name:        "context_escape",
		Re:          regexp.MustCompile(`(?i)(end\s+of\s+(system|user)\s+(message|prompt|input)|<\s*/?\s*(system|instruction|context)\s*>)`),
		Score:       0.5,
		Description: "コンテキスト脱出パターン",
	},
	{
		Name:        "prompt_leak",
		Re:          regexp.MustCompile(`(?i)(show|reveal|display|print|output|repeat)\s+(your\s+)?(system\s+prompt|instructions|initial\s+prompt|hidden\s+prompt)`),
		Score:       0.4,
		Description: "プロンプトリーク要求パターン",
	},
	{
		Name:        "jailbreak",
		Re:          regexp.MustCompile(`(?i)(DAN|do\s+anything\s+now|jailbreak|unlock\s+mode|developer\s+mode|god\s+mode|unrestricted\s+mode)`),
		Score:       0.5,
		Description: "ジェイルブレイクパターン",
	},
	{
		Name:        "unicode_homoglyph",
		Score:       0.3,
		Description: "Unicode ホモグリフ（スクリプト混在）の検出",
		Custom:      detectUnicodeHomoglyph,
	},
}

// base64Re は Base64 文字列を検出する正規表現。
// 20 文字以上の Base64 文字列を対象とする。
var base64Re = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// detectBase64Injection は Base64 エンコードされた命令を検出する。
func detectBase64Injection(text string) bool {
	matches := base64Re.FindAllString(text, 10)
	for _, m := range matches {
		decoded, err := base64.StdEncoding.DecodeString(padBase64(m))
		if err != nil {
			continue
		}
		decodedStr := strings.ToLower(string(decoded))
		// デコード結果に命令的なキーワードが含まれるか確認
		suspiciousKeywords := []string{
			"ignore", "system", "instructions", "prompt",
			"override", "execute", "admin", "password",
			"you are", "act as", "new task",
		}
		for _, kw := range suspiciousKeywords {
			if strings.Contains(decodedStr, kw) {
				return true
			}
		}
	}
	return false
}

// padBase64 は Base64 文字列をパディングする。
func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

// detectUnicodeHomoglyph はテキスト中のスクリプト混在を検出する。
// Latin + Cyrillic 等の混在は攻撃の兆候である。
func detectUnicodeHomoglyph(text string) bool {
	words := strings.Fields(text)
	for _, word := range words {
		if len([]rune(word)) < 3 {
			continue
		}
		if hasScriptMixing(word) {
			return true
		}
	}
	return false
}

// hasScriptMixing は単語内で複数の Unicode スクリプトが混在しているか検査する。
// Latin と Cyrillic/Greek の混在を検出する。
func hasScriptMixing(word string) bool {
	hasLatin := false
	hasCyrillic := false
	hasGreek := false

	for _, r := range word {
		if unicode.Is(unicode.Latin, r) {
			hasLatin = true
		}
		if unicode.Is(unicode.Cyrillic, r) {
			hasCyrillic = true
		}
		if unicode.Is(unicode.Greek, r) {
			hasGreek = true
		}
	}

	return hasLatin && (hasCyrillic || hasGreek)
}
