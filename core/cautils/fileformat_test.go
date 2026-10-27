package cautils

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
		{"separator with inline mapping", "--- {kind: Pod}", true},
		{"marker before invalid inline block mapping", "--- apiVersion: v1", true},
		{"comment without separation space", "---#not-a-marker", false},
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

// TestReadFileInlineYAMLDocuments checks valid document starts against yaml.v3 and the public file-loading APIs.
func TestReadFileInlineYAMLDocuments(t *testing.T) {
	first := "apiVersion: v1\nkind: Pod\nmetadata: {name: first}\n"
	second := "{apiVersion: v1, kind: Pod, metadata: {name: second}}"
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "inline flow mapping after block document", input: first + "--- " + second + "\n", want: []string{"first", "second"}},
		{name: "all inline documents", input: "--- {apiVersion: v1, kind: Pod, metadata: {name: first}}\n--- " + second + "\n", want: []string{"first", "second"}},
		{name: "tab after marker", input: first + "---\t" + second + "\n", want: []string{"first", "second"}},
		{name: "anchor after marker", input: first + "--- &resource " + second + "\n", want: []string{"first", "second"}},
		{name: "CRLF lines", input: strings.ReplaceAll(first+"--- "+second+"\n", "\n", "\r\n"), want: []string{"first", "second"}},
		{name: "standalone marker after inline document", input: first + "--- " + second + "\n--- # third document\napiVersion: v1\nkind: Pod\nmetadata: {name: third}\n", want: []string{"first", "second", "third"}},
		{name: "indented marker is scalar content", input: "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: first}\ndata:\n  script: |\n    --- {not: a document}\n", want: []string{"first"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := yaml.NewDecoder(strings.NewReader(tt.input))
			var referenceNames []string
			for {
				var object struct {
					Metadata struct {
						Name string `yaml:"name"`
					} `yaml:"metadata"`
				}
				err := decoder.Decode(&object)
				if errors.Is(err, io.EOF) {
					break
				}
				require.NoError(t, err, "the input must be a valid YAML stream")
				referenceNames = append(referenceNames, object.Metadata.Name)
			}
			require.Equal(t, tt.want, referenceNames)

			objects, err := ReadFile([]byte(tt.input), YAML_FILE_FORMAT)
			require.NoError(t, err)
			var names []string
			for _, object := range objects {
				names = append(names, object.GetName())
			}
			assert.Equal(t, tt.want, names)

			root := t.TempDir()
			path := filepath.Join(root, "inline.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.input), 0o600))
			loaded, skipped, err := LoadResourcesFromFiles(context.Background(), path, root, nil)
			require.NoError(t, err)
			assert.Empty(t, skipped)
			assert.Len(t, loaded[path], len(tt.want))
		})
	}
}

// TestReadFileInvalidInlineYAMLDocument reports a malformed trailing document while retaining complete earlier documents.
func TestReadFileInvalidInlineYAMLDocument(t *testing.T) {
	tests := []struct {
		name     string
		document string
	}{
		{name: "unterminated flow mapping", document: "--- {apiVersion: v1, kind: Pod, metadata: [\n"},
		{name: "invalid inline block mapping", document: "--- apiVersion: v1\nkind: Pod\nmetadata: {name: second}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "apiVersion: v1\nkind: Pod\nmetadata: {name: first}\n" + tt.document
			objects, err := ReadFile([]byte(input), YAML_FILE_FORMAT)
			require.Error(t, err)
			require.Len(t, objects, 1)
			assert.Equal(t, "first", objects[0].GetName())
			root := t.TempDir()
			path := filepath.Join(root, "invalid-inline.yaml")
			require.NoError(t, os.WriteFile(path, []byte(input), 0o600))
			loaded, skipped, err := LoadResourcesFromFiles(context.Background(), path, root, nil)
			require.Error(t, err)
			assert.Len(t, skipped, 1)
			require.Len(t, loaded[path], 1)
			assert.Equal(t, "first", loaded[path][0].GetName())
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
