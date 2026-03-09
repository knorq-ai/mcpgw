package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync/atomic"

	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
	"github.com/knorq-ai/mcpgw/internal/policy"
)

// ResponseInterceptor は S→C レスポンスに対するコンテンツスキャンと
// tools/list ホワイトリスト検証を行う。
type ResponseInterceptor struct {
	engine atomic.Pointer[policy.Engine]
}

// NewResponseInterceptor は ResponseInterceptor を生成する。
func NewResponseInterceptor(engine *policy.Engine) *ResponseInterceptor {
	r := &ResponseInterceptor{}
	r.engine.Store(engine)
	return r
}

// SwapEngine はポリシーエンジンをアトミックに入れ替える。
func (r *ResponseInterceptor) SwapEngine(e *policy.Engine) {
	r.engine.Store(e)
}

func (r *ResponseInterceptor) Intercept(_ context.Context, dir Direction, msg *jsonrpc.Message, raw []byte) Result {
	// C→S 方向は通過
	if dir == DirClientToServer {
		return Result{Action: ActionPass}
	}

	engine := r.engine.Load()
	if engine == nil {
		return Result{Action: ActionPass}
	}

	// レスポンスパターンスキャン（全 S→C メッセージ対象、サイズ制限あり）
	if patterns := engine.ResponsePatterns(); len(patterns) > 0 {
		if matched := scanResponseContent(raw, patterns); matched != nil {
			return Result{
				Action: ActionBlock,
				Reason: fmt.Sprintf("response matches forbidden pattern %q", matched.String()),
			}
		}
	}

	// tools/list レスポンス検証
	allowedTools := engine.AllowedTools()
	if len(allowedTools) > 0 && msg != nil && msg.IsResponse() && len(msg.Result) > 0 {
		if blocked := checkToolsList(msg.Result, allowedTools); blocked != "" {
			return Result{
				Action: ActionBlock,
				Reason: fmt.Sprintf("tools/list contains unauthorized tool %q", blocked),
			}
		}
	}

	return Result{Action: ActionPass}
}

// toolsListResult は tools/list レスポンスの構造。
type toolsListResult struct {
	Tools []toolEntry `json:"tools"`
}

type toolEntry struct {
	Name string `json:"name"`
}

// checkToolsList は tools/list レスポンスに許可されていないツールが含まれていないか確認する。
// 未許可ツールが見つかった場合はそのツール名を返す。見つからなければ空文字列。
func checkToolsList(result json.RawMessage, allowedTools []string) string {
	var tlr toolsListResult
	if err := json.Unmarshal(result, &tlr); err != nil {
		return "" // パースできない → tools/list レスポンスではない → 通過
	}
	if len(tlr.Tools) == 0 {
		return ""
	}
	for _, tool := range tlr.Tools {
		if !isToolAllowed(tool.Name, allowedTools) {
			return tool.Name
		}
	}
	return ""
}

// isToolAllowed はツール名が許可リストのいずれかにマッチするか判定する。
func isToolAllowed(name string, patterns []string) bool {
	for _, p := range patterns {
		if policy.GlobMatch(p, name) {
			return true
		}
	}
	return false
}

// maxResponseScanSize はレスポンスパターンスキャンの最大バイト数。
const maxResponseScanSize = 1024 * 1024

// scanResponseContent は raw バイト列に対してパターンマッチを行う。
// マッチしたパターンを返す。マッチしない場合は nil。
func scanResponseContent(raw []byte, patterns []*regexp.Regexp) *regexp.Regexp {
	if len(raw) > maxResponseScanSize {
		raw = raw[:maxResponseScanSize]
	}
	content := string(raw)
	for _, re := range patterns {
		if re.MatchString(content) {
			return re
		}
	}
	return nil
}
