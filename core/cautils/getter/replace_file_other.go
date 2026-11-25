//go:build !windows

package getter

import "os"

func replaceFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func openForRead(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0) // #nosec G304 -- caller supplied policy path
}
