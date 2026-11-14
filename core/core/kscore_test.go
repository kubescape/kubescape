package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKubescape_Context_NilSafety(t *testing.T) {
	t.Run("nil receiver returns background context", func(t *testing.T) {
		var ks *Kubescape
		ctx := ks.Context()
		assert.NotNil(t, ctx)
		assert.Equal(t, context.Background(), ctx)
	})

	t.Run("nil Ctx returns background context", func(t *testing.T) {
		ks := &Kubescape{Ctx: nil}
		ctx := ks.Context()
		assert.NotNil(t, ctx)
		assert.Equal(t, context.Background(), ctx)
	})

	t.Run("configured Ctx returns assigned context", func(t *testing.T) {
		type testKey string
		expectedCtx := context.WithValue(context.Background(), testKey("key"), "value")
		ks := NewKubescape(expectedCtx)
		assert.Equal(t, expectedCtx, ks.Context())
	})

	t.Run("SetContext handles nil receiver safely", func(t *testing.T) {
		var ks *Kubescape
		assert.NotPanics(t, func() {
			ks.SetContext(context.Background())
		})
	})

	t.Run("SetContext updates context", func(t *testing.T) {
		ks := NewKubescape(context.Background())
		type testKey string
		newCtx := context.WithValue(context.Background(), testKey("new"), "context")
		ks.SetContext(newCtx)
		assert.Equal(t, newCtx, ks.Context())
	})
}
