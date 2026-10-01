//go:build !windows

package cautils

import "os"

func atomicReplaceFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}
