package policy

import (
	"fmt"
	"sort"
	"strings"
)

// DiffType は差分の種別を表す。
type DiffType string

const (
	DiffAdded   DiffType = "added"
	DiffRemoved DiffType = "removed"
	DiffChanged DiffType = "changed"
)

// DiffEntry は差分の1エントリ。
type DiffEntry struct {
	Type    DiffType // added, removed, changed
	Section string   // "rule", "mode", "response_patterns", "allowed_tools"
	Name    string   // ルール名やフィールド名
	Old     string   // 変更前の値（added の場合は空）
	New     string   // 変更後の値（removed の場合は空）
}

// DiffResult はポリシー差分の全体結果。
type DiffResult struct {
	Entries []DiffEntry
}

// HasDiff は差分が存在するかを返す。
func (r *DiffResult) HasDiff() bool {
	return len(r.Entries) > 0
}

// String は差分を人間が読める形式で返す。
func (r *DiffResult) String() string {
	if !r.HasDiff() {
		return "差分なし"
	}
	var sb strings.Builder
	for _, e := range r.Entries {
		switch e.Type {
		case DiffAdded:
			sb.WriteString(fmt.Sprintf("+ [%s] %s: %s\n", e.Section, e.Name, e.New))
		case DiffRemoved:
			sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", e.Section, e.Name, e.Old))
		case DiffChanged:
			sb.WriteString(fmt.Sprintf("~ [%s] %s: %s → %s\n", e.Section, e.Name, e.Old, e.New))
		}
	}
	return sb.String()
}

// Diff は2つの PolicyFile を比較し、差分を返す。
func Diff(old, new *PolicyFile) *DiffResult {
	var entries []DiffEntry

	// mode の比較
	if old.Mode != new.Mode {
		entries = append(entries, DiffEntry{
			Type:    DiffChanged,
			Section: "mode",
			Name:    "mode",
			Old:     old.Mode,
			New:     new.Mode,
		})
	}

	// rules の比較
	entries = append(entries, diffRules(old.Rules, new.Rules)...)

	// response_patterns の比較
	entries = append(entries, diffStringSlice("response_patterns", old.ResponsePatterns, new.ResponsePatterns)...)

	// allowed_tools の比較
	entries = append(entries, diffStringSlice("allowed_tools", old.AllowedTools, new.AllowedTools)...)

	return &DiffResult{Entries: entries}
}

// diffRules はルールリストの差分を検出する。
// ルール名をキーとして追加・削除・変更を判定する。
func diffRules(oldRules, newRules []Rule) []DiffEntry {
	var entries []DiffEntry

	oldMap := make(map[string]Rule, len(oldRules))
	for _, r := range oldRules {
		oldMap[r.Name] = r
	}
	newMap := make(map[string]Rule, len(newRules))
	for _, r := range newRules {
		newMap[r.Name] = r
	}

	// 削除されたルール（old にあって new にない）
	for _, r := range oldRules {
		if _, ok := newMap[r.Name]; !ok {
			entries = append(entries, DiffEntry{
				Type:    DiffRemoved,
				Section: "rule",
				Name:    r.Name,
				Old:     formatRule(r),
			})
		}
	}

	// 追加されたルール（new にあって old にない）
	for _, r := range newRules {
		if _, ok := oldMap[r.Name]; !ok {
			entries = append(entries, DiffEntry{
				Type:    DiffAdded,
				Section: "rule",
				Name:    r.Name,
				New:     formatRule(r),
			})
		}
	}

	// 変更されたルール（両方に存在するが内容が異なる）
	for _, newRule := range newRules {
		oldRule, ok := oldMap[newRule.Name]
		if !ok {
			continue
		}
		changes := diffSingleRule(oldRule, newRule)
		if len(changes) > 0 {
			entries = append(entries, DiffEntry{
				Type:    DiffChanged,
				Section: "rule",
				Name:    newRule.Name,
				Old:     formatRule(oldRule),
				New:     formatRule(newRule),
			})
		}
	}

	return entries
}

// diffSingleRule は同名のルール間で変更されたフィールドのリストを返す。
func diffSingleRule(old, new Rule) []string {
	var changes []string

	if old.Action != new.Action {
		changes = append(changes, fmt.Sprintf("action: %s → %s", old.Action, new.Action))
	}
	if old.Mode != new.Mode {
		changes = append(changes, fmt.Sprintf("mode: %q → %q", old.Mode, new.Mode))
	}
	if !stringSliceEqual(old.Match.Methods, new.Match.Methods) {
		changes = append(changes, fmt.Sprintf("methods: %v → %v", old.Match.Methods, new.Match.Methods))
	}
	if !stringSliceEqual(old.Match.Tools, new.Match.Tools) {
		changes = append(changes, fmt.Sprintf("tools: %v → %v", old.Match.Tools, new.Match.Tools))
	}
	if !stringSliceEqual(old.Match.Subjects, new.Match.Subjects) {
		changes = append(changes, fmt.Sprintf("subjects: %v → %v", old.Match.Subjects, new.Match.Subjects))
	}
	if !stringMapSliceEqual(old.Match.Arguments, new.Match.Arguments) {
		changes = append(changes, "arguments changed")
	}
	if !stringMapSliceEqual(old.Match.ArgumentPatterns, new.Match.ArgumentPatterns) {
		changes = append(changes, "argument_patterns changed")
	}

	return changes
}

// formatRule はルールの概要を文字列として返す。
func formatRule(r Rule) string {
	parts := []string{fmt.Sprintf("action=%s", r.Action)}
	if r.Mode != "" {
		parts = append(parts, fmt.Sprintf("mode=%s", r.Mode))
	}
	parts = append(parts, fmt.Sprintf("methods=%v", r.Match.Methods))
	if len(r.Match.Tools) > 0 {
		parts = append(parts, fmt.Sprintf("tools=%v", r.Match.Tools))
	}
	if len(r.Match.Subjects) > 0 {
		parts = append(parts, fmt.Sprintf("subjects=%v", r.Match.Subjects))
	}
	if len(r.Match.Arguments) > 0 {
		parts = append(parts, fmt.Sprintf("arguments=%v", r.Match.Arguments))
	}
	if len(r.Match.ArgumentPatterns) > 0 {
		parts = append(parts, fmt.Sprintf("argument_patterns=%v", r.Match.ArgumentPatterns))
	}
	return strings.Join(parts, ", ")
}

// diffStringSlice は文字列スライスの差分を検出する。
func diffStringSlice(section string, old, new []string) []DiffEntry {
	var entries []DiffEntry

	oldSet := make(map[string]bool, len(old))
	for _, s := range old {
		oldSet[s] = true
	}
	newSet := make(map[string]bool, len(new))
	for _, s := range new {
		newSet[s] = true
	}

	// 削除された要素
	for _, s := range old {
		if !newSet[s] {
			entries = append(entries, DiffEntry{
				Type:    DiffRemoved,
				Section: section,
				Name:    s,
				Old:     s,
			})
		}
	}

	// 追加された要素
	for _, s := range new {
		if !oldSet[s] {
			entries = append(entries, DiffEntry{
				Type:    DiffAdded,
				Section: section,
				Name:    s,
				New:     s,
			})
		}
	}

	return entries
}

// stringSliceEqual は2つの文字列スライスが等しいかを返す。
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stringMapSliceEqual は map[string][]string の等価性を判定する。
func stringMapSliceEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || !stringSliceEqual(va, vb) {
			return false
		}
	}
	return true
}

// Summary は差分の要約を返す。
func (r *DiffResult) Summary() string {
	if !r.HasDiff() {
		return "差分なし"
	}

	added, removed, changed := 0, 0, 0
	sections := make(map[string]bool)
	for _, e := range r.Entries {
		sections[e.Section] = true
		switch e.Type {
		case DiffAdded:
			added++
		case DiffRemoved:
			removed++
		case DiffChanged:
			changed++
		}
	}

	sectionList := make([]string, 0, len(sections))
	for s := range sections {
		sectionList = append(sectionList, s)
	}
	sort.Strings(sectionList)

	return fmt.Sprintf("%d 件の差分 (追加=%d, 削除=%d, 変更=%d) 対象: %s",
		len(r.Entries), added, removed, changed, strings.Join(sectionList, ", "))
}
