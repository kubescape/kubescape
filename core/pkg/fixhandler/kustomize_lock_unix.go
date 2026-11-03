//go:build !windows

package fixhandler

import (
	"fmt"
	"os"
	"runtime"

	"github.com/gofrs/flock"
	"golang.org/x/sys/unix"
)

type unixKustomizeLock struct {
	fl       *flock.Flock
	lockPath string
}

func newKustomizeLock(lockPath string) (kustomizeLock, error) {
	flag := os.O_CREATE | unix.O_NOFOLLOW
	switch runtime.GOOS {
	case "aix", "solaris", "illumos":
		flag |= os.O_RDWR
	default:
		flag |= os.O_RDONLY
	}
	fl := flock.New(lockPath, flock.SetFlag(flag))
	return &unixKustomizeLock{fl: fl, lockPath: lockPath}, nil
}

func (l *unixKustomizeLock) TryLock() (bool, error) {
	locked, err := l.fl.TryLock()
	if err != nil {
		return false, err
	}
	if !locked {
		return false, nil
	}
	if fi, err := l.fl.Stat(); err == nil && (fi.Mode()&os.ModeSymlink != 0) {
		_ = l.fl.Unlock()
		return false, fmt.Errorf("output directory lock %q is a symbolic link", l.lockPath)
	}
	return true, nil
}

func (l *unixKustomizeLock) Unlock() error {
	return l.fl.Unlock()
}
