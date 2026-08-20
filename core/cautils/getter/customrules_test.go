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
	assert.NoError(t, err)
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
