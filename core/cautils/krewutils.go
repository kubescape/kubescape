package cautils

import (
	"os"
	"path/filepath"
	"strings"
)

// ExecName returns the correct name to use in examples depending on how kubescape is invoked
func ExecName() string {
	n := "kubescape"
	if IsKrewPlugin() {
		return "kubectl " + n
	}
	return n
}

func IsKrewPlugin() bool {
	return strings.HasPrefix(filepath.Base(os.Args[0]), "kubectl-")
}
