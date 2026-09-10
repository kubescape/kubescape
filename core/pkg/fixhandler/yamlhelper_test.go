package fixhandler

import (
	"context"
	"strings"
	"testing"

	"github.com/mikefarah/yq/v4/pkg/yqlib"
	"github.com/stretchr/testify/require"
)

// The shared reader is still used by JSON remediation and document counting.
func TestReadDocuments(t *testing.T) {
	for _, input := range []string{`{"first": true}`, `{"first": true}` + "\n" + `{"second": false}`} {
		docs, err := readDocuments(context.Background(), strings.NewReader(input), yqlib.NewJSONDecoder())
		require.NoError(t, err)
		index := uint(0)
		for e := docs.Front(); e != nil; e = e.Next() {
			node := e.Value.(*yqlib.CandidateNode)
			require.Equal(t, index, node.Document)
			require.True(t, node.EvaluateTogether)
			index++
		}
		require.Equal(t, uint(strings.Count(input, "\n")+1), index)
	}
	_, err := readDocuments(context.Background(), strings.NewReader(`{"broken":`), yqlib.NewJSONDecoder())
	require.Error(t, err)
}
