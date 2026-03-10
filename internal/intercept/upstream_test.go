package intercept

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpstreamContext(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", UpstreamFromContext(ctx))

	ctx = WithUpstream(ctx, "http://localhost:8080")
	assert.Equal(t, "http://localhost:8080", UpstreamFromContext(ctx))
}

func TestUpstreamContextOverwrite(t *testing.T) {
	ctx := WithUpstream(context.Background(), "http://a")
	ctx = WithUpstream(ctx, "http://b")
	assert.Equal(t, "http://b", UpstreamFromContext(ctx))
}
