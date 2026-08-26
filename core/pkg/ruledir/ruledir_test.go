package ruledir

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleMetadata = `{
  "name": "approve-csr-v1",
  "ruleLanguage": "Rego",
  "description": "subjects that can approve their own CSRs",
  "remediation": "Do not grant approve on signers",
  "ruleQuery": "armo_builtins",
  "match": [{"apiGroups": ["rbac.authorization.k8s.io"], "apiVersions": ["v1"], "resources": ["ClusterRole"]}]
}`

func writeRule(t *testing.T, parent, name string, files map[string]string) string {
	t.Helper()

	dir := filepath.Join(parent, name)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	for file, contents := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, file), []byte(contents), 0o600))
	}
	return dir
}

func completeRule(t *testing.T, parent, name string) string {
	t.Helper()

	return writeRule(t, parent, name, map[string]string{
		RegoFileName:     "package armo_builtins",
		MetadataFileName: sampleMetadata,
	})
}

func TestIs(t *testing.T) {
	parent := t.TempDir()

	complete := completeRule(t, parent, "complete")
	regoOnly := writeRule(t, parent, "rego-only", map[string]string{RegoFileName: "package armo_builtins"})
	metaOnly := writeRule(t, parent, "meta-only", map[string]string{MetadataFileName: sampleMetadata})

	assert.True(t, Is(complete))
	assert.False(t, Is(regoOnly))
	assert.False(t, Is(metaOnly))
	assert.False(t, Is(filepath.Join(parent, "missing")))
}

func TestLoadReadsMetadataAndRego(t *testing.T) {
	dir := completeRule(t, t.TempDir(), "approve-csr-v1")

	rule, ok, err := Load(dir)

	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "approve-csr-v1", rule.Name)
	assert.Equal(t, dir, rule.Dir)
	assert.Equal(t, "package armo_builtins", rule.Rule.Rule)
	assert.Equal(t, "Rego", string(rule.Rule.RuleLanguage))
	assert.Equal(t, "Do not grant approve on signers", rule.Rule.Remediation)

	require.Len(t, rule.Rule.Match, 1)
	assert.Equal(t, []string{"rbac.authorization.k8s.io"}, rule.Rule.Match[0].APIGroups)
	assert.Equal(t, []string{"ClusterRole"}, rule.Rule.Match[0].Resources)
}

func TestLoadNotARuleDirectory(t *testing.T) {
	dir := writeRule(t, t.TempDir(), "rego-only", map[string]string{RegoFileName: "package armo_builtins"})

	rule, ok, err := Load(dir)

	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Zero(t, rule)
}

func TestLoadMalformedMetadata(t *testing.T) {
	dir := writeRule(t, t.TempDir(), "broken", map[string]string{
		RegoFileName:     "package armo_builtins",
		MetadataFileName: `{"name": `,
	})

	_, _, err := Load(dir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), MetadataFileName)
}

func TestDiscoverReturnsChildrenInNameOrder(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"c-rule", "a-rule", "b-rule"} {
		completeRule(t, root, name)
	}
	writeRule(t, root, "not-a-rule", map[string]string{"README.md": "ignored"})
	require.NoError(t, os.WriteFile(filepath.Join(root, "loose.rego"), []byte("package armo_builtins"), 0o600))

	rules, err := Discover(root)

	require.NoError(t, err)
	require.Len(t, rules, 3)
	assert.Equal(t, "a-rule", rules[0].Name)
	assert.Equal(t, "b-rule", rules[1].Name)
	assert.Equal(t, "c-rule", rules[2].Name)
}

func TestDiscoverMissingRoot(t *testing.T) {
	_, err := Discover(filepath.Join(t.TempDir(), "missing"))
	assert.Error(t, err)
}

func TestDiscoverPathAcceptsARuleDirectoryOrItsParent(t *testing.T) {
	root := t.TempDir()
	dir := completeRule(t, root, "approve-csr-v1")

	fromParent, err := DiscoverPath(root)
	require.NoError(t, err)
	require.Len(t, fromParent, 1)

	fromRule, err := DiscoverPath(dir)
	require.NoError(t, err)
	require.Len(t, fromRule, 1)

	assert.Equal(t, fromParent[0].Name, fromRule[0].Name)
	assert.Equal(t, fromParent[0].Dir, fromRule[0].Dir)
}

// TestDiscoverRepositoryRules pins the loader against the layout this
// repository actually ships, so a change to either side is caught here.
func TestDiscoverRepositoryRules(t *testing.T) {
	rules, err := Discover(filepath.Join("..", "..", "..", "rules"))

	require.NoError(t, err)
	require.NotEmpty(t, rules)
	for _, rule := range rules {
		assert.NotEmpty(t, rule.Rule.Rule, "rule %s: %s must be loaded", rule.Name, RegoFileName)
		assert.NotEmpty(t, rule.Rule.Name, "rule %s: metadata must carry a name", rule.Name)
	}
}
