package getter

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestListWithPaginationRejectsRepeatedContinuationToken(t *testing.T) {
	calls := 0
	err := ListWithPagination(context.Background(), func(opts metav1.ListOptions) (string, error) {
		calls++
		if calls == 1 {
			assert.Empty(t, opts.Continue)
			return "stalled", nil
		}
		assert.Equal(t, "stalled", opts.Continue)
		return "stalled", nil
	})

	require.ErrorIs(t, err, ErrPaginationTokenRepeated)
	assert.Contains(t, err.Error(), `"stalled"`)
	assert.Equal(t, 2, calls, "the repeated cursor must stop pagination immediately")
}

func TestListWithPaginationRejectsContinuationTokenCycle(t *testing.T) {
	tokens := []string{"page-a", "page-b", "page-a"}
	calls := 0
	err := ListWithPagination(context.Background(), func(_ metav1.ListOptions) (string, error) {
		token := tokens[calls]
		calls++
		return token, nil
	})

	require.ErrorIs(t, err, ErrPaginationTokenRepeated)
	assert.Equal(t, 3, calls)
}

func TestListWithPaginationAllowsDistinctTokens(t *testing.T) {
	tokens := []string{"page-a", "page-b", ""}
	var requested []string
	err := ListWithPagination(context.Background(), func(opts metav1.ListOptions) (string, error) {
		requested = append(requested, opts.Continue)
		return tokens[len(requested)-1], nil
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"", "page-a", "page-b"}, requested)
}

func TestListWithPaginationPreservesListErrors(t *testing.T) {
	want := errors.New("api unavailable")
	err := ListWithPagination(context.Background(), func(metav1.ListOptions) (string, error) {
		return "", want
	})

	require.ErrorIs(t, err, want)
}
