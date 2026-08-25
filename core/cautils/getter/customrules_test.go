package getter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadCustomRules_EmptyPath(t *testing.T) {
	fw, err := LoadCustomRules("")
	assert.NoError(t, err)
	assert.Nil(t, fw)
}

func TestLoadCustomRules_DirDoesNotExist(t *testing.T) {
	_, err := LoadCustomRules("/does/not/exist/custom-rules")
	assert.Error(t, err)
}

func TestLoadCustomRules_NoRegoFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "not-a-rule.txt"), []byte("hello"), 0o600))

	fw, err := LoadCustomRules(dir)
	assert.Error(t, err)
	assert.Nil(t, fw)
}

func TestLoadCustomRules_WrongExtension(t *testing.T) {
	f := filepath.Join(t.TempDir(), "not-a-rule.txt")
	require.NoError(t, os.WriteFile(f, []byte("hello"), 0o600))

	fw, err := LoadCustomRules(f)
	assert.Error(t, err)
	assert.Nil(t, fw)
}

func TestLoadCustomRules_FromDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "no-privileged.rego"), []byte(`package armo_builtins

deny[{"alertMessage": msg}] { msg := "privileged container found" }`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "no-root.rego"), []byte(`package armo_builtins

deny[{"alertMessage": msg}] { msg := "root user found" }`), 0o600))

	fw, err := LoadCustomRules(dir)
	require.NoError(t, err)
	require.NotNil(t, fw)

	assert.Equal(t, "custom-rules", fw.Name)
	assert.Len(t, fw.Controls, 2)
	assert.Equal(t, "custom-no-privileged", fw.Controls[0].ControlID)
	assert.Equal(t, "custom-no-root", fw.Controls[1].ControlID)
	assert.Len(t, fw.Controls[0].Rules, 1)
	assert.Contains(t, fw.Controls[0].Rules[0].Rule, "package armo_builtins")
	assert.Equal(t, "Rego", string(fw.Controls[0].Rules[0].RuleLanguage))
	assert.Len(t, fw.Controls[0].Rules[0].Match, 1)
	assert.Equal(t, []string{"*"}, fw.Controls[0].Rules[0].Match[0].APIGroups)
}

func TestLoadCustomRules_FromSingleFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "no-privileged.rego")
	require.NoError(t, os.WriteFile(f, []byte(`package armo_builtins

deny[{"alertMessage": msg}] { msg := "ok" }`), 0o600))

	fw, err := LoadCustomRules(f)
	require.NoError(t, err)
	require.NotNil(t, fw)
	assert.Len(t, fw.Controls, 1)
	assert.Equal(t, "custom-no-privileged", fw.Controls[0].ControlID)
}

// writeRuleDir creates a rule directory in the layout used by the repository's
// rules/ tree: raw.rego next to rule.metadata.json.
func writeRuleDir(t *testing.T, parent, name, metadata string) string {
	t.Helper()

	dir := filepath.Join(parent, name)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "raw.rego"), []byte(`package armo_builtins

deny[{"alertMessage": msg}] { msg := "finding" }`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rule.metadata.json"), []byte(metadata), 0o600))
	return dir
}

const rbacRuleMetadata = `{
  "name": "approve-csr-v1",
  "ruleLanguage": "Rego",
  "description": "subjects that can approve their own CSRs",
  "remediation": "Do not grant approve on signers",
  "ruleQuery": "armo_builtins",
  "match": [{"apiGroups": ["rbac.authorization.k8s.io"], "apiVersions": ["v1"], "resources": ["ClusterRole"]}]
}`

func TestLoadCustomRules_FromRuleDirectory(t *testing.T) {
	dir := t.TempDir()
	writeRuleDir(t, dir, "approve-csr-v1", rbacRuleMetadata)

	fw, err := LoadCustomRules(dir)
	require.NoError(t, err)
	require.NotNil(t, fw)

	require.Len(t, fw.Controls, 1)
	control := fw.Controls[0]
	assert.Equal(t, "custom-approve-csr-v1", control.ControlID)
	assert.Equal(t, "subjects that can approve their own CSRs", control.Description)
	assert.Equal(t, "Do not grant approve on signers", control.Remediation)

	require.Len(t, control.Rules, 1)
	rule := control.Rules[0]
	assert.Contains(t, rule.Rule, "package armo_builtins")
	assert.Equal(t, "Rego", string(rule.RuleLanguage))

	// The declared selectors are kept, so the rule is only evaluated against
	// the kinds it targets instead of every collected resource.
	require.Len(t, rule.Match, 1)
	assert.Equal(t, []string{"rbac.authorization.k8s.io"}, rule.Match[0].APIGroups)
	assert.Equal(t, []string{"ClusterRole"}, rule.Match[0].Resources)
}

func TestLoadCustomRules_SingleRuleDirectoryPath(t *testing.T) {
	dir := writeRuleDir(t, t.TempDir(), "approve-csr-v1", rbacRuleMetadata)

	fw, err := LoadCustomRules(dir)
	require.NoError(t, err)
	require.NotNil(t, fw)

	require.Len(t, fw.Controls, 1)
	assert.Equal(t, "custom-approve-csr-v1", fw.Controls[0].ControlID)
}

func TestLoadCustomRules_MixedLayouts(t *testing.T) {
	dir := t.TempDir()
	writeRuleDir(t, dir, "approve-csr-v1", rbacRuleMetadata)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "no-root.rego"), []byte(`package armo_builtins

deny[{"alertMessage": msg}] { msg := "root user found" }`), 0o600))

	fw, err := LoadCustomRules(dir)
	require.NoError(t, err)
	require.NotNil(t, fw)

	ids := make([]string, 0, len(fw.Controls))
	for _, control := range fw.Controls {
		ids = append(ids, control.ControlID)
	}
	assert.ElementsMatch(t, []string{"custom-approve-csr-v1", "custom-no-root"}, ids)
}

func TestLoadCustomRules_RuleDirectoriesAreOrdered(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"c-rule", "a-rule", "b-rule"} {
		writeRuleDir(t, dir, name, `{"name":"`+name+`","ruleLanguage":"Rego","match":[]}`)
	}

	fw, err := LoadCustomRules(dir)
	require.NoError(t, err)

	require.Len(t, fw.Controls, 3)
	assert.Equal(t, "custom-a-rule", fw.Controls[0].ControlID)
	assert.Equal(t, "custom-b-rule", fw.Controls[1].ControlID)
	assert.Equal(t, "custom-c-rule", fw.Controls[2].ControlID)
}

func TestLoadCustomRules_RuleDirectoryWithoutMatchFallsBackToAllKinds(t *testing.T) {
	dir := t.TempDir()
	writeRuleDir(t, dir, "no-selectors", `{"name":"no-selectors","ruleLanguage":"Rego"}`)

	fw, err := LoadCustomRules(dir)
	require.NoError(t, err)

	require.Len(t, fw.Controls, 1)
	rule := fw.Controls[0].Rules[0]
	require.Len(t, rule.Match, 1)
	assert.Equal(t, []string{"*"}, rule.Match[0].Resources)
}

func TestLoadCustomRules_IncompleteRuleDirectoryIsIgnored(t *testing.T) {
	dir := t.TempDir()
	partial := filepath.Join(dir, "half-a-rule")
	require.NoError(t, os.MkdirAll(partial, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(partial, "raw.rego"), []byte("package armo_builtins"), 0o600))

	fw, err := LoadCustomRules(dir)

	// A directory holding only raw.rego is not a rule, and the error names both
	// files a caller needs to supply.
	require.Error(t, err)
	assert.Nil(t, fw)
	assert.Contains(t, err.Error(), "rule.metadata.json")
}

func TestLoadCustomRules_MalformedMetadataIsReported(t *testing.T) {
	dir := t.TempDir()
	writeRuleDir(t, dir, "broken", `{"name": `)

	_, err := LoadCustomRules(dir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule.metadata.json")
}

func TestLoadCustomRules_DuplicateNameAcrossLayoutsIsRejected(t *testing.T) {
	dir := t.TempDir()
	writeRuleDir(t, dir, "no-host-network", rbacRuleMetadata)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "no-host-network.rego"), []byte(`package armo_builtins

deny[{"alertMessage": msg}] { msg := "from the bare file" }`), 0o600))

	fw, err := LoadCustomRules(dir)

	// Both resolve to custom-no-host-network, and results are keyed by control
	// ID, so silently keeping one would drop a rule the user wrote.
	require.Error(t, err)
	assert.Nil(t, fw)
	assert.Contains(t, err.Error(), "no-host-network")
	assert.Contains(t, err.Error(), "defined twice")
}
