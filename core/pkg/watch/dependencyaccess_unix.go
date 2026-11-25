//go:build unix

package watch

import "golang.org/x/sys/unix"

func dependencyAccess(path string, directory bool) (readable, searchable bool) {
	// A directory can allow a known child to be opened while denying listings.
	readable = unix.Access(path, unix.R_OK) == nil
	searchable = !directory || unix.Access(path, unix.X_OK) == nil
	return readable, searchable
}
