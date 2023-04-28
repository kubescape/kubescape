package testutils

import (
	"runtime"
	"path/filepath"
)

func CurrentDir() string {
	_, filename, _, _ := runtime.Caller(1)

	return filepath.Dir(filename)
}
