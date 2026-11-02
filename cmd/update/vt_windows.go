//go:build windows

package update

import (
	"golang.org/x/sys/windows"
)

// supportsVirtualTerminal checks if the console attached to standard output
// has virtual terminal processing enabled, or attempts to enable it.
// If enabling fails (e.g. legacy cmd.exe without VT support), it returns false.
func supportsVirtualTerminal() bool {
	stdout := windows.Handle(windows.Stdout)
	var mode uint32
	if err := windows.GetConsoleMode(stdout, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(stdout, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
