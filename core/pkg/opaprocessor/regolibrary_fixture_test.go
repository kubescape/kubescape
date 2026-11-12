package opaprocessor

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/require"
)

const regolibraryModule = "github.com/kubescape/regolibrary/v2"

var (
	regolibraryDirOnce sync.Once
	regolibraryDirPath string
	regolibraryDirErr  error
)

// regolibraryDir returns the module-cache directory of the pinned regolibrary
// dependency, whose controls/ and rules/ trees are the shipped policy library.
func regolibraryDir(t *testing.T) string {
	t.Helper()
	regolibraryDirOnce.Do(func() {
		out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", regolibraryModule).Output()
		regolibraryDirPath, regolibraryDirErr = strings.TrimSpace(string(out)), err
	})
	require.NoError(t, regolibraryDirErr, "cannot locate the pinned %s module", regolibraryModule)
	require.NotEmpty(t, regolibraryDirPath)
	return regolibraryDirPath
}

// loadLibraryRule builds a PolicyRule from the pinned regolibrary: the real
// raw.rego plus the match block from rule.metadata.json.
func loadLibraryRule(t *testing.T, name string) reporthandling.PolicyRule {
	t.Helper()
	dir := filepath.Join(regolibraryDir(t), "rules", name)

	raw, err := os.ReadFile(filepath.Join(dir, "raw.rego"))
	require.NoError(t, err)
	meta, err := os.ReadFile(filepath.Join(dir, "rule.metadata.json"))
	require.NoError(t, err)

	var rule reporthandling.PolicyRule
	require.NoError(t, json.Unmarshal(meta, &rule))
	rule.Rule = string(raw)
	return rule
}

// loadLibraryControl builds a Control from the pinned regolibrary, with its
// rules resolved from rulesNames.
func loadLibraryControl(t *testing.T, controlFile string) reporthandling.Control {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(regolibraryDir(t), "controls", controlFile))
	require.NoError(t, err)

	var control reporthandling.Control
	require.NoError(t, json.Unmarshal(data, &control))
	var names struct {
		RulesNames []string `json:"rulesNames"`
	}
	require.NoError(t, json.Unmarshal(data, &names))
	for _, name := range names.RulesNames {
		// Some library controls name rules that ship no Rego source (for
		// example CEL-only rules); only Rego rules can be loaded here.
		if _, err := os.Stat(filepath.Join(regolibraryDir(t), "rules", name, "raw.rego")); err != nil {
			continue
		}
		control.Rules = append(control.Rules, loadLibraryRule(t, name))
	}
	return control
}
