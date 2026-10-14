package printer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitHubActionsPrinter_ReturnsWriteError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		score float32
	}{{"summary only", 0}, {"failed control annotation", 9}} {
		t.Run(tc.name, func(t *testing.T) {
			session := ghSessionFixture(t, "C-0057", tc.score)
			path := filepath.Join(t.TempDir(), "annotations.txt")
			require.NoError(t, os.WriteFile(path, []byte("existing output"), 0600))
			writer, err := os.Open(path)
			require.NoError(t, err)
			t.Cleanup(func() { _ = writer.Close() })
			gp := NewGitHubActionsPrinter()
			gp.writer = writer

			err = gp.ActionPrint(context.Background(), session, nil)
			require.Error(t, err, "failed annotation output must not be reported as successful")
			var pathError *os.PathError
			require.ErrorAs(t, err, &pathError)
			require.NoError(t, gp.CloseWriter(), "closing a read-only file succeeds and cannot detect the lost output")
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "existing output", string(raw))
		})
	}
}
