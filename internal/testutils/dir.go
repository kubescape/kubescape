package testutils

import (
	"path/filepath"
	"runtime"
)

// CurrentDir returns the directory of the file where this function is defined.
func CurrentDir() string {
	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		panic("failed to get current file info")
	}
	return filepath.Dir(filename)
}
