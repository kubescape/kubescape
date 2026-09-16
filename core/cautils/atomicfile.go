package cautils

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const atomicOutputDirPerm fs.FileMode = 0o750

// WriteFileAtomically replaces path with data without exposing a partially
// written file. The temporary file is created beside the destination so the
// final rename stays on the same filesystem and is atomic.
//
// Existing content remains untouched until all bytes have been written,
// flushed and closed successfully. A failure before the rename removes the
// temporary file and leaves the prior destination in place.
func WriteFileAtomically(path string, data []byte, perm fs.FileMode) (err error) {
	cleanPath := filepath.Clean(path)
	parent := filepath.Dir(cleanPath)
	if err := os.MkdirAll(parent, atomicOutputDirPerm); err != nil {
		return fmt.Errorf("create output directory for %q: %w", cleanPath, err)
	}

	temp, err := os.CreateTemp(parent, "."+filepath.Base(cleanPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary output for %q: %w", cleanPath, err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(perm); err != nil {
		return fmt.Errorf("set permissions on temporary output for %q: %w", cleanPath, err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write temporary output for %q: %w", cleanPath, err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("flush temporary output for %q: %w", cleanPath, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary output for %q: %w", cleanPath, err)
	}
	if err := atomicReplaceFile(tempPath, cleanPath); err != nil {
		return fmt.Errorf("replace output %q: %w", cleanPath, err)
	}
	committed = true
	return nil
}
