package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitTracer_NoopWhenEndpointEmpty(t *testing.T) {
	shutdown, err := InitTracer(Config{})
	require.NoError(t, err)
	require.NotNil(t, shutdown)

	// shutdown は何もせず成功する
	err = shutdown(context.Background())
	assert.NoError(t, err)
}

func TestInitTracer_DefaultServiceName(t *testing.T) {
	shutdown, err := InitTracer(Config{ServiceName: ""})
	require.NoError(t, err)
	defer shutdown(context.Background())

	// no-op トレーサーが設定される
	tracer := GlobalTracer()
	assert.NotNil(t, tracer)
}

func TestInitTracer_WithEndpoint(t *testing.T) {
	// endpoint が設定されていても現在は no-op で動作する
	shutdown, err := InitTracer(Config{
		OTLPEndpoint: "localhost:4317",
		ServiceName:  "test-service",
		SampleRate:   0.5,
	})
	require.NoError(t, err)
	defer shutdown(context.Background())
}

func TestNoopTracer_StartCreatesSpan(t *testing.T) {
	tracer := &noopTracer{}
	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()

	assert.NotNil(t, span)

	// コンテキストに trace ID と span ID が設定される
	traceID := TraceIDFromContext(ctx)
	assert.Len(t, traceID, 32, "trace ID は 32 hex 文字である")

	spanID := SpanIDFromContext(ctx)
	assert.Len(t, spanID, 16, "span ID は 16 hex 文字である")

	assert.Equal(t, spanID, span.SpanID())
}

func TestNoopTracer_PreservesExistingTraceID(t *testing.T) {
	existingTraceID := "0123456789abcdef0123456789abcdef"
	ctx := withTraceContext(context.Background(), existingTraceID, "")

	tracer := &noopTracer{}
	ctx, span := tracer.Start(ctx, "child-span")
	defer span.End()

	// 既存の trace ID が引き継がれる
	assert.Equal(t, existingTraceID, TraceIDFromContext(ctx))

	// span ID は新規生成される
	spanID := SpanIDFromContext(ctx)
	assert.Len(t, spanID, 16)
}

func TestNoopSpan_SetAttributeIsNoop(t *testing.T) {
	span := &noopSpan{spanID: "abcdef0123456789"}
	// パニックしないことを確認
	span.SetAttribute("key", "value")
	span.End()
	assert.Equal(t, "abcdef0123456789", span.SpanID())
}

func TestGenerateID_TraceID(t *testing.T) {
	id := generateID(16)
	assert.Len(t, id, 32, "trace ID は 32 hex 文字である")
}

func TestGenerateID_SpanID(t *testing.T) {
	id := generateID(8)
	assert.Len(t, id, 16, "span ID は 16 hex 文字である")
}

func TestGenerateID_Uniqueness(t *testing.T) {
	ids := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id := generateID(16)
		ids[id] = struct{}{}
	}
	assert.Equal(t, 100, len(ids), "100 個の ID が全て一意である")
}

func TestSetGlobalTracer(t *testing.T) {
	original := GlobalTracer()
	defer SetGlobalTracer(original)

	custom := &noopTracer{}
	SetGlobalTracer(custom)
	assert.Equal(t, custom, GlobalTracer())
}
