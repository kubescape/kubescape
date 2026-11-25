//go:build !unix

package watch

// Windows fsnotify does not emit attribute events.
func dependencyAccess(string, bool) (readable, searchable bool) {
	return true, true
}
