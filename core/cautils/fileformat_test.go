package cautils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsYAMLDocumentSeparator(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"standard separator", "---", true},
		{"separator with trailing spaces", "---   ", true},
		{"separator with comment", "--- # start", true},
		{"separator with tab", "---\t", true},
		{"separator with CR", "---\r", true},
		{"not a separator - content after", "---foo", false},
		{"not a separator - plain text", "hello", false},
		{"not a separator - dashes in text", "-- not enough", false},
		{"empty line", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isYAMLDocumentSeparator([]byte(tt.line)))
		})
	}
}

func TestMergeMaps(t *testing.T) {
	t.Run("override wins on conflict", func(t *testing.T) {
		base := map[string]any{"a": 1, "b": 2}
		over := map[string]any{"b": 99}
		got := mergeMaps(base, over)
		assert.Equal(t, 1, got["a"])
		assert.Equal(t, 99, got["b"])
	})

	t.Run("deep merge nested maps", func(t *testing.T) {
		base := map[string]any{
			"top": map[string]any{"x": 1, "y": 2},
		}
		over := map[string]any{
			"top": map[string]any{"y": 42, "z": 3},
		}
		got := mergeMaps(base, over)
		nested := got["top"].(map[string]any)
		assert.Equal(t, 1, nested["x"])
		assert.Equal(t, 42, nested["y"])
		assert.Equal(t, 3, nested["z"])
	})

	t.Run("does not mutate base", func(t *testing.T) {
		base := map[string]any{"k": "original"}
		over := map[string]any{"k": "changed"}
		mergeMaps(base, over)
		assert.Equal(t, "original", base["k"])
	})
}

func TestSplitYAMLDocuments(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{
			name:    "single document no separator",
			input:   "apiVersion: v1\nkind: Pod",
			wantLen: 1,
		},
		{
			name:    "two documents",
			input:   "apiVersion: v1\nkind: Pod\n---\napiVersion: v1\nkind: Service",
			wantLen: 2,
		},
		{
			name:    "leading separator is ignored",
			input:   "---\napiVersion: v1\nkind: Pod",
			wantLen: 1,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "only separators",
			input:   "---\n---\n---",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs, err := splitYAMLDocuments([]byte(tt.input))
			require.NoError(t, err)
			assert.Len(t, docs, tt.wantLen)
		})
	}
}

// erroringReader yields data once, then fails with a fixed error instead of
// io.EOF, simulating a read failure partway through a multi-document file
// (e.g. a truncated stream or an I/O error on the underlying source).
type erroringReader struct {
	data []byte
	pos  int
	err  error
}

func (e *erroringReader) Read(p []byte) (int, error) {
	if e.pos >= len(e.data) {
		return 0, e.err
	}
	n := copy(p, e.data[e.pos:])
	e.pos += n
	return n, nil
}

// TestScanYAMLDocuments_PropagatesReaderError guards against a scan failure
// being silently swallowed: a multi-document file with a read error after the
// first document must surface that error to the caller, not just return the
// documents seen before the failure as if they were the whole file.
func TestScanYAMLDocuments_PropagatesReaderError(t *testing.T) {
	wantErr := errors.New("boom: connection reset")
	input := "apiVersion: v1\nkind: Pod\n---\napiVersion: v1\nkind: Service"
	r := &erroringReader{data: []byte(input), err: wantErr}

	docs, err := scanYAMLDocuments(r, len(input)+1)

	require.Error(t, err, "a scan failure must be reported, not swallowed")
	assert.ErrorIs(t, err, wantErr)
	// The first document, terminated by a real "---" separator before the
	// failure, is still valid and returned; the second was never read and
	// must not appear as if the file only ever had one document.
	assert.Len(t, docs, 1)
}
