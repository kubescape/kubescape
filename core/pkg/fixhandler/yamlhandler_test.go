package fixhandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDecodeDocumentRoots(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "single document",
			input:     "apiVersion: v1\nkind: Pod\n",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "two documents separated by ---",
			input:     "apiVersion: v1\nkind: Pod\n---\napiVersion: v1\nkind: Service\n",
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "empty string",
			input:     "",
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:      "invalid yaml",
			input:     ":\n  :\n    - :\n  [invalid",
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes, err := decodeDocumentRoots(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, nodes, tt.wantCount)
			}
		})
	}
}

func TestRemoveNewLinesAtTheEnd(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no trailing newlines",
			input:    []string{"line1", "line2"},
			expected: []string{"line1", "line2"},
		},
		{
			name:     "one trailing newline",
			input:    []string{"line1", "line2", "\n"},
			expected: []string{"line1", "line2"},
		},
		{
			name:     "multiple trailing newlines",
			input:    []string{"line1", "line2", "\n", "\n"},
			expected: []string{"line1", "line2"},
		},
		{
			name:     "single element non-newline",
			input:    []string{"line1"},
			expected: []string{"line1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeNewLinesAtTheEnd(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFlattenWithDFS(t *testing.T) {
	t.Run("simple scalar node", func(t *testing.T) {
		node := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: "hello",
		}
		result := flattenWithDFS(node)
		require.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, "hello", (*result)[0].node.Value)
		assert.Nil(t, (*result)[0].parent)
	})

	t.Run("mapping node with one key-value pair", func(t *testing.T) {
		node := &yaml.Node{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "key"},
				{Kind: yaml.ScalarNode, Value: "value"},
			},
		}
		result := flattenWithDFS(node)
		require.NotNil(t, result)
		// Root (mapping) + 2 children (key, value) = 3 nodes
		assert.Len(t, *result, 3)
		assert.Equal(t, yaml.MappingNode, (*result)[0].node.Kind)
		assert.Equal(t, "key", (*result)[1].node.Value)
		assert.Equal(t, "value", (*result)[2].node.Value)
	})

	t.Run("sequence node with items", func(t *testing.T) {
		node := &yaml.Node{
			Kind: yaml.SequenceNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "item1"},
				{Kind: yaml.ScalarNode, Value: "item2"},
			},
		}
		result := flattenWithDFS(node)
		require.NotNil(t, result)
		// Root (sequence) + 2 children = 3 nodes
		assert.Len(t, *result, 3)
	})

	t.Run("parent references are set correctly", func(t *testing.T) {
		parent := &yaml.Node{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "key"},
				{Kind: yaml.ScalarNode, Value: "value"},
			},
		}
		result := flattenWithDFS(parent)
		require.NotNil(t, result)
		// First node (root) has no parent
		assert.Nil(t, (*result)[0].parent)
		// Children reference the root as their parent
		assert.Equal(t, parent, (*result)[1].parent)
		assert.Equal(t, parent, (*result)[2].parent)
	})
}
