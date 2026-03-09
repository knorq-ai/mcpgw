package pii

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Pattern は PII パターンの定義。
type Pattern struct {
	Name     string           // パターン名
	Re       *regexp.Regexp   // 検出用正規表現
	Severity float64          // 重要度スコア (0.0-1.0)
	Validate func(string) bool // 追加バリデーション（nil の場合は正規表現マッチのみ）
}

// allPatterns は定義済みの全パターン。
var allPatterns = []*Pattern{
	patternCreditCard,
	patternSSN,
	patternEmail,
	patternPhone,
	patternAWSAccessKey,
	patternAWSSecretKey,
	patternHighEntropyToken,
}

// patternsByName は名前をキーとするパターンマップ。
var patternsByName map[string]*Pattern

func init() {
	patternsByName = make(map[string]*Pattern, len(allPatterns))
	for _, p := range allPatterns {
		patternsByName[p.Name] = p
	}
}

// クレジットカード番号 (Visa, MC, Amex, Discover)
// ハイフンまたはスペース区切りを許容する。
var patternCreditCard = &Pattern{
	Name:     "credit_card",
	Re:       regexp.MustCompile(`\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{1,4}\b`),
	Severity: 0.95,
	Validate: luhnCheck,
}

// 米国社会保障番号 (SSN)
var patternSSN = &Pattern{
	Name:     "ssn",
	Re:       regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`),
	Severity: 0.95,
	Validate: validateSSN,
}

// メールアドレス
var patternEmail = &Pattern{
	Name:     "email",
	Re:       regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
	Severity: 0.5,
	Validate: nil,
}

// 米国電話番号
var patternPhone = &Pattern{
	Name:     "phone",
	Re:       regexp.MustCompile(`\b(?:\+?1[\s\-.]?)?\(?[0-9]{3}\)?[\s\-.]?[0-9]{3}[\s\-.]?[0-9]{4}\b`),
	Severity: 0.4,
	Validate: nil,
}

// AWS アクセスキー ID
var patternAWSAccessKey = &Pattern{
	Name:     "aws_key",
	Re:       regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	Severity: 0.9,
	Validate: nil,
}

// AWS シークレットキー (40 文字の Base64 風文字列)
var patternAWSSecretKey = &Pattern{
	Name:     "aws_secret",
	Re:       regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`),
	Severity: 0.85,
	Validate: func(s string) bool {
		// エントロピーが低い場合は誤検出
		return shannonEntropy(s) >= 3.5
	},
}

// 高エントロピートークン (32 文字以上の Base64 文字列)
var patternHighEntropyToken = &Pattern{
	Name:     "high_entropy_token",
	Re:       regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`),
	Severity: 0.7,
	Validate: func(s string) bool {
		return shannonEntropy(s) >= 4.0
	},
}

// luhnCheck は Luhn アルゴリズムでクレジットカード番号を検証する。
func luhnCheck(s string) bool {
	// 非数字文字を除去
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// validateSSN は SSN の基本的な構造バリデーションを行う。
// 000, 666, 900-999 で始まる番号や 00/0000 を含む番号を除外する。
func validateSSN(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	area, _ := strconv.Atoi(parts[0])
	group, _ := strconv.Atoi(parts[1])
	serial, _ := strconv.Atoi(parts[2])

	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if group == 0 || serial == 0 {
		return false
	}
	return true
}

// shannonEntropy は文字列のシャノンエントロピーを計算する。
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
