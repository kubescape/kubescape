package fixhandler

import (
	"context"
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
		},
		{
			name:      "two documents separated by ---",
			input:     "apiVersion: v1\nkind: Pod\n---\napiVersion: v1\nkind: Service\n",
			wantCount: 2,
		},
		{
			name:      "empty string",
			input:     "",
			wantCount: 0,
		},
		{
			name:    "invalid yaml",
			input:   "metadata:\n  name: test\n  bad: [",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes, err := decodeDocumentRoots(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, nodes, tt.wantCount)
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
		assert.Len(t, *result, 3)
	})

	t.Run("parent references and indexes are set correctly", func(t *testing.T) {
		var root yaml.Node
		require.NoError(t, yaml.Unmarshal([]byte("metadata:\n  name: demo\nspec:\n  replicas: 2\n"), &root))

		result := flattenWithDFS(&root)
		require.NotNil(t, result)
		require.GreaterOrEqual(t, len(*result), 7)
		assert.Same(t, &root, (*result)[0].node)
		assert.Nil(t, (*result)[0].parent)
		assert.Equal(t, 0, (*result)[0].index)
		assert.Same(t, &root, (*result)[1].parent)
		assert.Equal(t, 0, (*result)[1].index)
	})
}

func TestGetFixedNodes(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expression string
		assert     func(t *testing.T, got []yaml.Node)
		wantError  bool
	}{
		{
			name:       "updates scalar value",
			input:      "spec:\n  replicas: 1\n",
			expression: ".spec.replicas = 3",
			assert: func(t *testing.T, got []yaml.Node) {
				require.Len(t, got, 1)
				var out map[string]map[string]int
				require.NoError(t, got[0].Decode(&out))
				assert.Equal(t, 3, out["spec"]["replicas"])
			},
		},
		{
			name:       "adds mapping key",
			input:      "metadata:\n  name: demo\n",
			expression: ".metadata.namespace = \"default\"",
			assert: func(t *testing.T, got []yaml.Node) {
				require.Len(t, got, 1)
				var out map[string]map[string]string
				require.NoError(t, got[0].Decode(&out))
				assert.Equal(t, "default", out["metadata"]["namespace"])
			},
		},
		{
			name:       "invalid expression",
			input:      "kind: Pod\n",
			expression: ".kind = ",
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getFixedNodes(context.Background(), tt.input, tt.expression)
			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			tt.assert(t, got)
		})
	}
}
