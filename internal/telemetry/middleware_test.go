package telemetry

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_GeneratesTraceID(t *testing.T) {
	var capturedTraceID, capturedSpanID string

	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTraceID = TraceIDFromContext(r.Context())
		capturedSpanID = SpanIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Len(t, capturedTraceID, 32, "trace ID は 32 hex 文字である")
	assert.Len(t, capturedSpanID, 16, "span ID は 16 hex 文字である")

	// レスポンスに traceparent ヘッダが付与される
	tp := rec.Header().Get("Traceparent")
	assert.NotEmpty(t, tp)
	assert.Contains(t, tp, capturedTraceID)
	assert.Contains(t, tp, capturedSpanID)
}

func TestMiddleware_PropagatesIncomingTraceparent(t *testing.T) {
	incomingTraceID := "0af7651916cd43dd8448eb211c80319c"
	incomingTP := "00-" + incomingTraceID + "-b7ad6b7169203331-01"

	var capturedTraceID string

	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTraceID = TraceIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Traceparent", incomingTP)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// 受信した trace ID が伝播される
	assert.Equal(t, incomingTraceID, capturedTraceID)

	// レスポンスの traceparent には同じ trace ID が含まれる
	tp := rec.Header().Get("Traceparent")
	assert.Contains(t, tp, incomingTraceID)
}

func TestMiddleware_IgnoresInvalidTraceparent(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := TraceIDFromContext(r.Context())
		// 不正な traceparent は無視され、新規 trace ID が生成される
		assert.Len(t, traceID, 32)
		assert.NotEqual(t, "invalid", traceID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Traceparent", "invalid-header-value")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_TraceparentFormat(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	tp := rec.Header().Get("Traceparent")
	require.NotEmpty(t, tp)

	// "00-{trace_id}-{span_id}-{flags}" フォーマットを検証
	traceID, spanID, flags, ok := parseTraceparent(tp)
	assert.True(t, ok)
	assert.Len(t, traceID, 32)
	assert.Len(t, spanID, 16)
	assert.Equal(t, "01", flags)
}

func TestParseTraceparent_Valid(t *testing.T) {
	traceID, spanID, flags, ok := parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	assert.True(t, ok)
	assert.Equal(t, "0af7651916cd43dd8448eb211c80319c", traceID)
	assert.Equal(t, "b7ad6b7169203331", spanID)
	assert.Equal(t, "01", flags)
}

func TestParseTraceparent_InvalidVersion(t *testing.T) {
	_, _, _, ok := parseTraceparent("01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	assert.False(t, ok)
}

func TestParseTraceparent_WrongPartCount(t *testing.T) {
	_, _, _, ok := parseTraceparent("00-abc-01")
	assert.False(t, ok)
}

func TestParseTraceparent_InvalidTraceIDLength(t *testing.T) {
	_, _, _, ok := parseTraceparent("00-0af765-b7ad6b7169203331-01")
	assert.False(t, ok)
}

func TestParseTraceparent_InvalidSpanIDLength(t *testing.T) {
	_, _, _, ok := parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad-01")
	assert.False(t, ok)
}

func TestParseTraceparent_NonHexTraceID(t *testing.T) {
	_, _, _, ok := parseTraceparent("00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01")
	assert.False(t, ok)
}

func TestParseTraceparent_AllZeroTraceID(t *testing.T) {
	_, _, _, ok := parseTraceparent("00-00000000000000000000000000000000-b7ad6b7169203331-01")
	assert.False(t, ok)
}

func TestParseTraceparent_AllZeroSpanID(t *testing.T) {
	_, _, _, ok := parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01")
	assert.False(t, ok)
}

func TestFormatTraceparent(t *testing.T) {
	result := formatTraceparent("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331", "01")
	assert.Equal(t, "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", result)
}

func TestIsHex_Valid(t *testing.T) {
	assert.True(t, isHex("0af7651916cd43dd"))
	assert.True(t, isHex("0123456789abcdef"))
}

func TestIsHex_Invalid(t *testing.T) {
	assert.False(t, isHex("xyz"))
	assert.False(t, isHex("0af7651916cd43d")) // 奇数長
}

func TestIsAllZero(t *testing.T) {
	assert.True(t, isAllZero("00000000"))
	assert.False(t, isAllZero("00000001"))
	assert.False(t, isAllZero("a0000000"))
}

func TestMiddleware_SetsHTTPMethodAttribute(t *testing.T) {
	// no-op スパンは属性を記録しないが、パニックしないことを確認する
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		req := httptest.NewRequest(method, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}
