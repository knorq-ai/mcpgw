package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTraceIDFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", TraceIDFromContext(ctx))
}

func TestTraceIDFromContext_Set(t *testing.T) {
	traceID := "0123456789abcdef0123456789abcdef"
	ctx := withTraceContext(context.Background(), traceID, "abcdef0123456789")
	assert.Equal(t, traceID, TraceIDFromContext(ctx))
}

func TestSpanIDFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", SpanIDFromContext(ctx))
}

func TestSpanIDFromContext_Set(t *testing.T) {
	spanID := "abcdef0123456789"
	ctx := withTraceContext(context.Background(), "0123456789abcdef0123456789abcdef", spanID)
	assert.Equal(t, spanID, SpanIDFromContext(ctx))
}

func TestWithTraceContext_Overwrites(t *testing.T) {
	ctx := withTraceContext(context.Background(), "aaaa", "bbbb")
	ctx = withTraceContext(ctx, "cccc", "dddd")
	assert.Equal(t, "cccc", TraceIDFromContext(ctx))
	assert.Equal(t, "dddd", SpanIDFromContext(ctx))
}
