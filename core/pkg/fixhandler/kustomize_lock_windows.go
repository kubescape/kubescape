//go:build windows

package fixhandler

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

type windowsKustomizeLock struct {
	path string
	m    sync.Mutex
	h    windows.Handle
	l    bool
}

func newKustomizeLock(lockPath string) (kustomizeLock, error) {
	return &windowsKustomizeLock{path: lockPath, h: windows.InvalidHandle}, nil
}

func (l *windowsKustomizeLock) TryLock() (bool, error) {
	l.m.Lock()
	defer l.m.Unlock()

	if l.l {
		return true, nil
	}

	if l.h == 0 || l.h == windows.InvalidHandle {
		pathPtr, err := windows.UTF16PtrFromString(l.path)
		if err != nil {
			return false, err
		}

		// Open with FILE_FLAG_OPEN_REPARSE_POINT so CreateFile opens the reparse point itself
		// rather than following it to any target outside the destination directory.
		h, err := windows.CreateFile(
			pathPtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_ALWAYS,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
			0,
		)
		if err != nil {
			if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
				return false, nil
			}
			return false, err
		}

		// Reject if the opened file is a symbolic link or reparse point.
		var fi windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
			_ = windows.CloseHandle(h)
			return false, err
		}
		if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			_ = windows.CloseHandle(h)
			return false, fmt.Errorf("output directory lock %q is a symbolic link or reparse point", l.path)
		}

		l.h = h
	}

	err := windows.LockFileEx(l.h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if err != nil && !errors.Is(err, windows.Errno(0)) {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			_ = windows.CloseHandle(l.h)
			l.h = windows.InvalidHandle
			return false, nil
		}
		_ = windows.CloseHandle(l.h)
		l.h = windows.InvalidHandle
		return false, err
	}

	l.l = true
	return true, nil
}

func (l *windowsKustomizeLock) Unlock() error {
	l.m.Lock()
	defer l.m.Unlock()

	if !l.l || l.h == 0 || l.h == windows.InvalidHandle {
		if l.h != 0 && l.h != windows.InvalidHandle {
			_ = windows.CloseHandle(l.h)
			l.h = windows.InvalidHandle
		}
		return nil
	}

	err := windows.UnlockFileEx(l.h, 0, 1, 0, &windows.Overlapped{})
	_ = windows.CloseHandle(l.h)
	l.h = windows.InvalidHandle
	l.l = false
	if err != nil && !errors.Is(err, windows.Errno(0)) {
		return err
	}
	return nil
}
