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

func TestYAMLEditorCompatibility(t *testing.T) {
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
			fixed, err := ApplyFixToContent(context.Background(), tt.input, tt.expression)
			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			got, err := decodeDocumentRoots(fixed)
			require.NoError(t, err)
			tt.assert(t, got)
		})
	}
}
