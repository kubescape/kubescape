//go:build linux

package version

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func readPTY(f *os.File) ([]byte, error) {
	var buf bytes.Buffer
	b := make([]byte, 1024)
	for {
		n, err := f.Read(b)
		if n > 0 {
			buf.Write(b[:n])
		}
		if err != nil {
			var pathErr *os.PathError
			if errors.Is(err, io.EOF) || errors.Is(err, syscall.EIO) || (errors.As(err, &pathErr) && errors.Is(pathErr.Err, syscall.EIO)) {
				return buf.Bytes(), nil
			}
			return buf.Bytes(), err
		}
	}
}

func openPTY(t *testing.T) (*os.File, *os.File) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("skipping terminal test: /dev/ptmx unavailable: %v", err)
	}

	var ptn uint32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, ptmx.Fd(), unix.TIOCGPTN, uintptr(unsafe.Pointer(&ptn)))
	if errno != 0 {
		_ = ptmx.Close()
		t.Skipf("skipping terminal test: TIOCGPTN failed: %v", errno)
	}

	var unlock uint32
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, ptmx.Fd(), unix.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock)))
	if errno != 0 {
		_ = ptmx.Close()
		t.Skipf("skipping terminal test: TIOCSPTLCK failed: %v", errno)
	}

	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptn), os.O_RDWR, 0)
	if err != nil {
		_ = ptmx.Close()
		t.Skipf("skipping terminal test: opening slave pty failed: %v", err)
	}

	return ptmx, pts
}

func cleanSubprocessEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "FORCE_COLOR=") || strings.HasPrefix(kv, "NO_COLOR=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

func TestGetVersionCmd_FreshProcess_Terminal_EmptyNoColor(t *testing.T) {
	master, slave := openPTY(t)
	defer master.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Version", "--")
	cmd.Env = cleanSubprocessEnv(
		"GO_WANT_HELPER_PROCESS=1",
		"KS_SKIP_UPDATE_CHECK=true",
		"NO_COLOR=",
		"TERM=xterm-256color",
	)
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Stdin = slave

	require.NoError(t, cmd.Start())
	_ = slave.Close()

	out, err := readPTY(master)
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())

	outStr := string(out)
	assert.Contains(t, outStr, "\x1b[", "terminal output with empty NO_COLOR must include ANSI colors without FORCE_COLOR")
	assert.Contains(t, outStr, "Your current version is: ")
	assert.Contains(t, outStr, "v3.0.1")
}

func TestGetVersionCmd_FreshProcess_Terminal_NonEmptyNoColor(t *testing.T) {
	master, slave := openPTY(t)
	defer master.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Version", "--")
	cmd.Env = cleanSubprocessEnv(
		"GO_WANT_HELPER_PROCESS=1",
		"KS_SKIP_UPDATE_CHECK=true",
		"NO_COLOR=1",
		"TERM=xterm-256color",
	)
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Stdin = slave

	require.NoError(t, cmd.Start())
	_ = slave.Close()

	out, err := readPTY(master)
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())

	outStr := string(out)
	assert.NotContains(t, outStr, "\x1b[", "terminal output with non-empty NO_COLOR must have zero ANSI escapes")
	assert.Contains(t, outStr, "Your current version is: v3.0.1")
}
