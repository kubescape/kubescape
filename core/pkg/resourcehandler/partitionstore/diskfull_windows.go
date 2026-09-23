//go:build windows

package partitionstore

import (
	"errors"
	"syscall"
)

// On Windows syscall.ENOSPC is a value invented by Go that the OS never
// returns; a full volume is reported as ERROR_HANDLE_DISK_FULL or
// ERROR_DISK_FULL instead.
const (
	errorHandleDiskFull syscall.Errno = 39
	errorDiskFull       syscall.Errno = 112
)

func isPlatformDiskFull(err error) bool {
	return errors.Is(err, errorDiskFull) || errors.Is(err, errorHandleDiskFull)
}
