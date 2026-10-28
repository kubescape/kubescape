package policytest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadCaseInputYAMLExtensions verifies that fixture discovery accepts the same YAML suffixes as normal manifest scans.
func TestLoadCaseInputYAMLExtensions(t *testing.T) {
	const manifest = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: fixture\n"
	tests := []struct {
		name    string
		content string
		count   int
		wantErr bool
	}{
		{name: "resource.yaml", content: manifest, count: 1},
		{name: "resource.yml", content: manifest, count: 1},
		{name: "resource.YAML", content: manifest, count: 1},
		{name: "resource.YML", content: manifest, count: 1},
		{name: "resource.YaMl", content: manifest, count: 1},
		{name: "resource.YmL", content: manifest, count: 1},
		{name: "notes.txt", content: "not a manifest"},
		{name: "resource.yaml.bak", content: manifest},
		{name: "broken.YAML", content: "metadata: [", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "input")
			require.NoError(t, os.MkdirAll(filepath.Join(input, "nested.yaml"), 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(input, "nested.yaml", "ignored.yaml"), []byte(manifest), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(input, tt.name), []byte(tt.content), 0o600))

			resources, err := LoadCaseInput(root)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.name)
				return
			}
			require.NoError(t, err)
			require.Len(t, resources, tt.count)
			if tt.count > 0 {
				assert.Equal(t, "fixture", resources[0].GetName())
			}
		})
	}
}

// TestRunRuleUppercaseYAMLInput verifies real rule evaluation and prevents empty expectations from passing over ignored input.
func TestRunRuleUppercaseYAMLInput(t *testing.T) {
	for _, extension := range []string{".YAML", ".YML", ".YaMl"} {
		t.Run(extension, func(t *testing.T) {
			for _, emptyExpected := range []bool{false, true} {
				name := "matching expectations"
				if emptyExpected {
					name = "empty expectations must fail"
				}
				t.Run(name, func(t *testing.T) {
					rule := scaffoldedRuleUnderTest(t)
					c := caseByName(t, rule, flaggedCaseName)
					input := filepath.Join(c.Dir, "input")
					require.NoError(t, os.Rename(filepath.Join(input, "resource.yaml"), filepath.Join(input, "resource"+extension)))
					if emptyExpected {
						require.NoError(t, os.WriteFile(filepath.Join(c.Dir, expectedFileName), []byte("[]\n"), 0o600))
					}
					rule.Cases = []Case{c}
					results := RunRule(context.Background(), rule)
					require.Len(t, results, 1)
					require.NoError(t, results[0].Err)
					assert.Equal(t, !emptyExpected, results[0].Passed, results[0].Diff)
				})
			}
		})
	}
}
