package fixhandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSplitYAMLPipeline(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        []string
		errContains string
	}{
		{
			name:  "single expression without pipe",
			input: `.spec.replicas = 2`,
			want:  []string{`.spec.replicas = 2`},
		},
		{
			name:  "splits top-level pipes while preserving update operator",
			input: `.a |= "x" | .b = "y|z" | .c = ["1|2"]`,
			want:  []string{`.a |= "x" `, ` .b = "y|z" `, ` .c = ["1|2"]`},
		},
		{
			name:  "ignores escaped quotes inside string",
			input: `.a = "he\"|llo" | .b = true`,
			want:  []string{`.a = "he\"|llo" `, ` .b = true`},
		},
		{
			name:        "unbalanced closing bracket",
			input:       `.a = 1]`,
			errContains: "unbalanced YAML edit",
		},
		{
			name:        "unterminated string",
			input:       `.a = "unclosed`,
			errContains: "unterminated YAML edit",
		},
		{
			name:        "unterminated bracket",
			input:       `.a = [1, 2`,
			errContains: "unterminated YAML edit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitYAMLPipeline(tt.input)
			if tt.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseYAMLPath(t *testing.T) {
	t.Run("parses keys, numeric indices, wildcards, and quoted keys", func(t *testing.T) {
		got, err := parseYAMLPath(`spec.containers[0].env[*]."app.kubernetes.io/name"`)
		require.NoError(t, err)
		assert.Equal(t, []yamlPathPart{
			{key: "spec"},
			{key: "containers"},
			{sequence: true, index: 0},
			{key: "env"},
			{sequence: true, wildcard: true},
			{key: "app.kubernetes.io/name"},
		}, got)
	})

	t.Run("rejects unsafe or malformed paths", func(t *testing.T) {
		for _, bad := range []string{"", "spec[abc]", "spec..name", "spec;drop"} {
			_, err := parseYAMLPath(bad)
			require.Error(t, err, "expected error for path %q", bad)
		}
	})
}

func TestIsYAMLBoolean(t *testing.T) {
	for _, s := range []string{"true", "false", "True", "False", "TRUE", "FALSE"} {
		assert.True(t, isYAMLBoolean(s), "expected %q to be boolean", s)
	}
	for _, s := range []string{"", "yes", "no", "1", "0", "tRuE"} {
		assert.False(t, isYAMLBoolean(s), "expected %q not to be boolean", s)
	}
}

func TestParseYAMLLiteral(t *testing.T) {
	t.Run("quoted string unescapes double quotes only", func(t *testing.T) {
		node, err := parseYAMLLiteral(`"say \"hi\"\n"`)
		require.NoError(t, err)
		assert.Equal(t, yaml.ScalarNode, node.Kind)
		assert.Equal(t, "!!str", node.Tag)
		assert.Equal(t, `say "hi"\n`, node.Value)
	})

	t.Run("boolean literal is lowercased", func(t *testing.T) {
		node, err := parseYAMLLiteral("TRUE")
		require.NoError(t, err)
		assert.Equal(t, "!!bool", node.Tag)
		assert.Equal(t, "true", node.Value)
	})

	t.Run("numeric literals", func(t *testing.T) {
		intNode, err := parseYAMLLiteral("42")
		require.NoError(t, err)
		assert.Equal(t, "!!int", intNode.Tag)
		assert.Equal(t, "42", intNode.Value)

		floatNode, err := parseYAMLLiteral("3.5")
		require.NoError(t, err)
		assert.Equal(t, "!!float", floatNode.Tag)
		assert.Equal(t, "3.5", floatNode.Value)
	})

	t.Run("flow sequence and mapping literals", func(t *testing.T) {
		seqNode, err := parseYAMLLiteral(`["one", 2, true]`)
		require.NoError(t, err)
		assert.Equal(t, yaml.SequenceNode, seqNode.Kind)
		assert.Len(t, seqNode.Content, 3)

		mapNode, err := parseYAMLLiteral(`{"enabled": true}`)
		require.NoError(t, err)
		assert.Equal(t, yaml.MappingNode, mapNode.Kind)
	})

	t.Run("rejects non-literals and unsafe expressions", func(t *testing.T) {
		for _, bad := range []string{
			`"a" + "b"`,
			`NaN`,
			`Inf`,
			`null`,
			`env(HOME)`,
			`["unterminated]`,
			`[null]`,
		} {
			_, err := parseYAMLLiteral(bad)
			require.Error(t, err, "expected error for literal %q", bad)
		}
	})
}

func TestParseYAMLOperations(t *testing.T) {
	t.Run("empty or whitespace expression returns nil", func(t *testing.T) {
		ops, err := parseYAMLOperations("   ")
		require.NoError(t, err)
		assert.Nil(t, ops)
	})

	t.Run("parses document selector, assignment, append, and delete", func(t *testing.T) {
		expr := `select(di==1).spec.replicas = 3 | select(di==0) | .spec.args += ["--safe"] | del(.metadata.annotations)`
		ops, err := parseYAMLOperations(expr)
		require.NoError(t, err)
		require.Len(t, ops, 3)

		assert.Equal(t, 1, ops[0].document)
		assert.Equal(t, "=", ops[0].kind)
		assert.Equal(t, "3", ops[0].value.Value)

		assert.Equal(t, 0, ops[1].document)
		assert.Equal(t, "+=", ops[1].kind)
		assert.Equal(t, yaml.SequenceNode, ops[1].value.Kind)

		assert.Equal(t, -1, ops[2].document)
		assert.Equal(t, "del", ops[2].kind)
		assert.Nil(t, ops[2].value)
	})

	t.Run("rejects malformed operations", func(t *testing.T) {
		for _, bad := range []string{
			`spec.replicas = 1`,
			`.spec.replicas`,
			`.spec.replicas = notALiteral`,
		} {
			_, err := parseYAMLOperations(bad)
			require.Error(t, err, "expected error for expression %q", bad)
		}
	})
}
