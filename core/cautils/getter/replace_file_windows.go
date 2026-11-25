//go:build windows

package getter

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

const (
	replaceFileAttempts = 20
	replaceFileDelay    = 25 * time.Millisecond
)

// replaceFile renames oldPath over newPath. Windows refuses to replace a file
// that another handle has open (access denied or sharing violation), which is
// normally gone within milliseconds, so those two errors are retried briefly.
func replaceFile(oldPath, newPath string) error {
	var err error
	for attempt := 0; attempt < replaceFileAttempts; attempt++ {
		err = os.Rename(oldPath, newPath)
		if err == nil || !isTransientReplaceError(err) {
			return err
		}
		time.Sleep(replaceFileDelay)
	}
	return err
}

func isTransientReplaceError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
