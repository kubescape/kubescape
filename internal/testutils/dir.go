package testutils

import (
	"path/filepath"
	"runtime"
)

// CurrentDir returns the directory of the file where this function is defined.
func CurrentDir() string {
	_, filename, ok := runtime.Caller(0)
	if !ok {
		panic("failed to get current file info")
	}
	return filepath.Dir(filename)
}
