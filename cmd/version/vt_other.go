//go:build !windows

package version

// supportsVirtualTerminal returns true on non-Windows platforms where ANSI
// sequences are handled natively by terminal emulators.
func supportsVirtualTerminal() bool {
	return true
}
