package resources

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRegoDependenciesFromDir(t *testing.T) {
	dir, _ := os.Getwd()
	t.Errorf("%s", filepath.Join(dir, "rego/dependencies"))
	return
	// modules := LoadRegoDependenciesFromDir("")
	// if len(modules) == 0 {
	// 	t.Errorf("modules len == 0")
	// }
}
