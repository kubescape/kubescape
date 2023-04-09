package testutils

import (
	"path/filepath"
	"runtime"
)

func CurrentDir() string {
	_, filename, _, _ := runtime.Caller(1)

	return filepath.Dir(filename)
}
