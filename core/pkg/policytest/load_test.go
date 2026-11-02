package policytest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
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

// TestLoadCaseInputJSON verifies that fixture discovery reads JSON manifests,
// which a scan of local files accepts too, instead of skipping them.
func TestLoadCaseInputJSON(t *testing.T) {
	const manifest = `{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "fixture"}}`
	tests := []struct {
		name    string
		content string
		names   []string
		wantErr bool
	}{
		{name: "resource.json", content: manifest, names: []string{"fixture"}},
		{name: "resource.JSON", content: manifest, names: []string{"fixture"}},
		{
			name:    "array.json",
			content: `[{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "first"}}, {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "second"}}]`,
			names:   []string{"first", "second"},
		},
		{
			name:    "list.json",
			content: `{"apiVersion": "v1", "kind": "List", "items": [{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "item"}}]}`,
			names:   []string{"item"},
		},
		{name: "resource.json.bak", content: manifest},
		{name: "broken.json", content: `{"apiVersion": "v1",`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "input")
			require.NoError(t, os.MkdirAll(input, 0o750))
			require.NoError(t, os.WriteFile(filepath.Join(input, tt.name), []byte(tt.content), 0o600))

			resources, err := LoadCaseInput(root)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.name)
				return
			}
			require.NoError(t, err)
			var names []string
			for _, r := range resources {
				names = append(names, r.GetName())
			}
			assert.Equal(t, tt.names, names)
		})
	}
}

// TestRunRuleJSONInput verifies real rule evaluation of a JSON fixture and
// that an empty expectation cannot pass over it.
func TestRunRuleJSONInput(t *testing.T) {
	for _, emptyExpected := range []bool{false, true} {
		name := "matching expectations"
		if emptyExpected {
			name = "empty expectations must fail"
		}
		t.Run(name, func(t *testing.T) {
			rule := scaffoldedRuleUnderTest(t)
			c := caseByName(t, rule, flaggedCaseName)
			input := filepath.Join(c.Dir, "input")
			// The same manifest Scaffold wrote as resource.yaml, as JSON.
			manifest := workloadKinds["Deployment"].manifest(rule.Name, containersBlock(true))
			converted, err := yaml.YAMLToJSON([]byte(manifest))
			require.NoError(t, err)
			require.NoError(t, os.Remove(filepath.Join(input, "resource.yaml")))
			require.NoError(t, os.WriteFile(filepath.Join(input, "resource.json"), converted, 0o600))
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
