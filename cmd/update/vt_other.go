//go:build !windows

package update

// supportsVirtualTerminal returns true on non-Windows platforms where ANSI
// sequences are handled natively by terminal emulators.
func supportsVirtualTerminal() bool {
	return true
}
