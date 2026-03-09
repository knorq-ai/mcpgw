// Package schema はツール引数の JSON Schema 検証プラグインを提供する。
// tools/list レスポンスからスキーマを取得・キャッシュし、
// tools/call の引数をスキーマ検証する。
package schema

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"

	"github.com/knorq-ai/mcpgw/internal/intercept"
	"github.com/knorq-ai/mcpgw/internal/jsonrpc"
)

// Plugin はスキーマ検証プラグイン。
type Plugin struct {
	cache  *SchemaCache
	strict bool // unknown properties を拒否するか
}

// New は未初期化の Plugin を生成する。
func New() *Plugin {
	return &Plugin{}
}

// Name はプラグイン名を返す。
func (p *Plugin) Name() string { return "schema" }

// Init は設定に基づいてプラグインを初期化する。
// config キー:
//   - strict: unknown properties を拒否するか (デフォルト: false)
func (p *Plugin) Init(config map[string]any) error {
	p.cache = NewSchemaCache()
	if v, ok := config["strict"]; ok {
		if b, ok := v.(bool); ok {
			p.strict = b
		}
	}
	return nil
}

// Close はリソースを解放する。
func (p *Plugin) Close() error { return nil }

// Intercept はスキーマ検証を実行する。
// S→C: tools/list レスポンスからスキーマをキャッシュ
// C→S: tools/call の引数をスキーマ検証
func (p *Plugin) Intercept(ctx context.Context, dir intercept.Direction, msg *jsonrpc.Message, raw []byte) intercept.Result {
	if msg == nil {
		return intercept.Result{Action: intercept.ActionPass}
	}

	switch dir {
	case intercept.DirServerToClient:
		// tools/list レスポンスからスキーマを抽出・キャッシュ
		p.cacheToolSchemas(msg)
		return intercept.Result{Action: intercept.ActionPass}

	case intercept.DirClientToServer:
		// tools/call の引数をスキーマ検証
		if msg.Method != "tools/call" {
			return intercept.Result{Action: intercept.ActionPass}
		}
		return p.validateToolCall(msg)
	}

	return intercept.Result{Action: intercept.ActionPass}
}

// toolEntry は tools/list レスポンス内のツール定義。
type toolEntry struct {
	Name        string          `json:"name"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// toolsListResult は tools/list レスポンスの result 構造。
type toolsListResult struct {
	Tools []toolEntry `json:"tools"`
}

// cacheToolSchemas は tools/list レスポンスからスキーマを抽出・キャッシュする。
func (p *Plugin) cacheToolSchemas(msg *jsonrpc.Message) {
	if len(msg.Result) == 0 {
		return
	}

	var result toolsListResult
	if json.Unmarshal(msg.Result, &result) != nil {
		return
	}

	for _, tool := range result.Tools {
		if tool.Name != "" && len(tool.InputSchema) > 0 {
			p.cache.Set(tool.Name, tool.InputSchema)
			slog.Debug("cached tool schema", "tool", tool.Name)
		}
	}
}

// validateToolCall は tools/call の引数をスキーマ検証する。
func (p *Plugin) validateToolCall(msg *jsonrpc.Message) intercept.Result {
	if len(msg.Params) == 0 {
		return intercept.Result{Action: intercept.ActionPass}
	}

	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(msg.Params, &params) != nil {
		return intercept.Result{Action: intercept.ActionPass}
	}

	if params.Name == "" {
		return intercept.Result{Action: intercept.ActionPass}
	}

	schemaRaw, ok := p.cache.Get(params.Name)
	if !ok {
		// スキーマ未キャッシュ → fail-open で通過
		return intercept.Result{Action: intercept.ActionPass}
	}

	// JSON Schema の基本的な検証
	// 完全な JSON Schema 検証は外部ライブラリが必要なため、
	// ここでは required/type の基本チェックのみ実施する
	errors := p.basicSchemaValidate(schemaRaw, params.Arguments)
	if len(errors) == 0 {
		return intercept.Result{Action: intercept.ActionPass}
	}

	return intercept.Result{
		Action:      intercept.ActionBlock,
		Reason:      fmt.Sprintf("schema validation failed for tool %q: %v", params.Name, errors),
		RuleName:    "schema:" + params.Name,
		ThreatType:  "schema_violation",
		ThreatScore: 0.6,
		ThreatDetails: map[string]any{
			"tool":   params.Name,
			"errors": errors,
		},
	}
}

// simpleSchema は JSON Schema の基本構造。
type simpleSchema struct {
	Type       string                     `json:"type"`
	Required   []string                   `json:"required,omitempty"`
	Properties map[string]json.RawMessage `json:"properties,omitempty"`
}

// propertySchema はプロパティごとの型情報。
type propertySchema struct {
	Type string `json:"type"`
}

// basicSchemaValidate は JSON Schema の基本的な検証を行う。
// required フィールドの存在チェックと type チェックを実施する。
func (p *Plugin) basicSchemaValidate(schemaRaw json.RawMessage, argsRaw json.RawMessage) []string {
	var schema simpleSchema
	if json.Unmarshal(schemaRaw, &schema) != nil {
		return nil // スキーマパース不能 → fail-open
	}

	if schema.Type != "object" && schema.Type != "" {
		return nil
	}

	var args map[string]json.RawMessage
	if json.Unmarshal(argsRaw, &args) != nil {
		if len(schema.Required) > 0 {
			return []string{"arguments is not a valid JSON object"}
		}
		return nil
	}

	var errors []string

	// required チェック
	for _, req := range schema.Required {
		if _, ok := args[req]; !ok {
			errors = append(errors, fmt.Sprintf("missing required field %q", req))
		}
	}

	// strict モードでは unknown properties を拒否
	if p.strict && len(schema.Properties) > 0 {
		for key := range args {
			if _, ok := schema.Properties[key]; !ok {
				errors = append(errors, fmt.Sprintf("unknown property %q", key))
			}
		}
	}

	// プロパティの型チェック
	for key, valRaw := range args {
		propRaw, ok := schema.Properties[key]
		if !ok {
			continue // スキーマに定義がないプロパティはスキップ
		}
		var prop propertySchema
		if json.Unmarshal(propRaw, &prop) != nil || prop.Type == "" {
			continue // 型宣言がない場合はスキップ
		}
		if err := checkJSONType(key, valRaw, prop.Type); err != "" {
			errors = append(errors, err)
		}
	}

	return errors
}

// checkJSONType は値の JSON 型が期待する型と一致するか検証する。
// 不一致の場合はエラーメッセージを返し、一致する場合は空文字列を返す。
func checkJSONType(field string, raw json.RawMessage, expected string) string {
	var val any
	if json.Unmarshal(raw, &val) != nil {
		return fmt.Sprintf("field %q has invalid JSON value", field)
	}

	actual := jsonTypeName(val)

	switch expected {
	case "integer":
		// JSON の number のうち小数部がないものを integer とみなす
		if actual == "number" {
			n, _ := val.(float64)
			if n == math.Trunc(n) && !math.IsInf(n, 0) && !math.IsNaN(n) {
				return ""
			}
		}
		if actual != "number" {
			return fmt.Sprintf("field %q has type %s, expected integer", field, actual)
		}
		// actual == "number" だが小数部がある場合
		return fmt.Sprintf("field %q has type number (non-integer), expected integer", field)
	case "number":
		// JSON の number なら integer でも number でも許容する
		if actual == "number" {
			return ""
		}
		return fmt.Sprintf("field %q has type %s, expected number", field, actual)
	default:
		if actual != expected {
			return fmt.Sprintf("field %q has type %s, expected %s", field, actual, expected)
		}
		return ""
	}
}

// jsonTypeName は Go の any 値から JSON 型名を返す。
func jsonTypeName(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}
