//go:build windows

package partitionstore

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDiskFull_WindowsErrors(t *testing.T) {
	// Windows never returns syscall.ENOSPC: a full volume surfaces as
	// ERROR_DISK_FULL (112) or ERROR_HANDLE_DISK_FULL (39), wrapped by os.
	for _, errno := range []syscall.Errno{112, 39} {
		err := &os.PathError{Op: "write", Path: `C:\Temp\kubescape-spill-1\partitions\6e732d61.jsonl`, Err: errno}
		assert.True(t, isDiskFull(err), "errno %d: %v", uintptr(errno), err)
		assert.True(t, isDiskFull(fmt.Errorf("failed to write record: %w", err)), "errno %d wrapped", uintptr(errno))
	}
	assert.False(t, isDiskFull(&os.PathError{Op: "open", Path: `C:\Temp\x`, Err: syscall.ERROR_ACCESS_DENIED}))
}
