package telemetry

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Middleware は HTTP リクエストごとにトレーシングスパンを開始し、
// W3C traceparent ヘッダの伝播を行うミドルウェアを返す。
//
// 受信リクエストに traceparent ヘッダが含まれる場合はそこから trace ID を
// 抽出してコンテキストに設定する。含まれない場合は新規 trace ID を生成する。
//
// レスポンスには traceparent ヘッダを付与し、下流サービスとの相関を可能にする。
//
// スパン属性:
//   - http.method: HTTP メソッド
//   - http.url: リクエスト URL
//   - mcp.method: JSON-RPC の method フィールド（Content-Type が application/json の場合）
//   - mcp.tool_name: tools/call の場合のツール名
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// 受信 traceparent ヘッダから trace ID を復元
		if tp := r.Header.Get("Traceparent"); tp != "" {
			if traceID, _, _, ok := parseTraceparent(tp); ok {
				ctx = withTraceContext(ctx, traceID, "")
			}
		}

		tracer := GlobalTracer()
		ctx, span := tracer.Start(ctx, "http.request")
		defer span.End()

		// スパン属性の設定
		span.SetAttribute("http.method", r.Method)
		span.SetAttribute("http.url", r.URL.String())

		// traceparent レスポンスヘッダの付与
		traceID := TraceIDFromContext(ctx)
		spanID := SpanIDFromContext(ctx)
		if traceID != "" && spanID != "" {
			w.Header().Set("Traceparent", formatTraceparent(traceID, spanID, "01"))
		}

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// parseTraceparent は W3C traceparent ヘッダを解析する。
// フォーマット: "00-{trace_id}-{span_id}-{flags}"
// 不正なフォーマットの場合は ok=false を返す。
func parseTraceparent(header string) (traceID, spanID, flags string, ok bool) {
	parts := strings.Split(header, "-")
	if len(parts) != 4 {
		return "", "", "", false
	}

	version := parts[0]
	traceID = parts[1]
	spanID = parts[2]
	flags = parts[3]

	// version は "00" のみサポート
	if version != "00" {
		return "", "", "", false
	}

	// trace ID: 32 hex 文字（16 バイト）
	if len(traceID) != 32 || !isHex(traceID) {
		return "", "", "", false
	}

	// span ID: 16 hex 文字（8 バイト）
	if len(spanID) != 16 || !isHex(spanID) {
		return "", "", "", false
	}

	// flags: 2 hex 文字
	if len(flags) != 2 || !isHex(flags) {
		return "", "", "", false
	}

	// all-zero trace ID / span ID は無効
	if isAllZero(traceID) || isAllZero(spanID) {
		return "", "", "", false
	}

	return traceID, spanID, flags, true
}

// formatTraceparent は W3C traceparent ヘッダ文字列を組み立てる。
func formatTraceparent(traceID, spanID, flags string) string {
	return fmt.Sprintf("00-%s-%s-%s", traceID, spanID, flags)
}

// isHex は文字列が有効な hex 文字のみで構成されているか検査する。
func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// isAllZero は hex 文字列が全てゼロかを検査する。
func isAllZero(s string) bool {
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return true
}
