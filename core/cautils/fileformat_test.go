package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		base := map[string]interface{}{"a": 1, "b": 2}
		over := map[string]interface{}{"b": 99}
		got := mergeMaps(base, over)
		assert.Equal(t, 1, got["a"])
		assert.Equal(t, 99, got["b"])
	})

	t.Run("deep merge nested maps", func(t *testing.T) {
		base := map[string]interface{}{
			"top": map[string]interface{}{"x": 1, "y": 2},
		}
		over := map[string]interface{}{
			"top": map[string]interface{}{"y": 42, "z": 3},
		}
		got := mergeMaps(base, over)
		nested := got["top"].(map[string]interface{})
		assert.Equal(t, 1, nested["x"])
		assert.Equal(t, 42, nested["y"])
		assert.Equal(t, 3, nested["z"])
	})

	t.Run("does not mutate base", func(t *testing.T) {
		base := map[string]interface{}{"k": "original"}
		over := map[string]interface{}{"k": "changed"}
		mergeMaps(base, over)
		assert.Equal(t, "original", base["k"])
	})
}

func TestSplitYAMLDocuments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
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
			docs := splitYAMLDocuments([]byte(tt.input))
			assert.Len(t, docs, tt.wantLen)
		})
	}
}
