//go:build linux

package update

import (
	"bytes"
	"context"
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

func TestGetUpdateCmd_FreshProcess_Terminal_EmptyNoColor(t *testing.T) {
	master, slave := openPTY(t)
	defer master.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Update", "--")
	cmd.Env = cleanSubprocessEnv(
		"GO_WANT_HELPER_PROCESS=1",
		"TEST_UPDATE_MODE=available",
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
	assert.Contains(t, outStr, "Version")
	assert.Contains(t, outStr, "v3.1.0")
}

func TestGetUpdateCmd_FreshProcess_Terminal_NonEmptyNoColor(t *testing.T) {
	master, slave := openPTY(t)
	defer master.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess_Update", "--")
	cmd.Env = cleanSubprocessEnv(
		"GO_WANT_HELPER_PROCESS=1",
		"TEST_UPDATE_MODE=available",
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
	assert.Contains(t, outStr, "Version v3.1.0 is available.")
}

func TestGetUpdateCmd_SplitStreams_StdoutTerminal(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	os.Unsetenv("NO_COLOR")
	t.Setenv("FORCE_COLOR", "")
	os.Unsetenv("FORCE_COLOR")

	master, slave := openPTY(t)
	defer master.Close()

	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)
	cmd.SetOut(slave)
	cmd.SetArgs([]string{"--format", "text"})

	require.NoError(t, cmd.Execute())
	_ = slave.Close()

	outBytes, err := readPTY(master)
	require.NoError(t, err)
	outStr := string(outBytes)

	assert.Contains(t, outStr, "\x1b[", "terminal stdout must have ANSI colors")
	assert.Contains(t, outStr, "Version")
	assert.Contains(t, outStr, "v3.1.0")
}

func TestGetUpdateCmd_SplitStreams_StdoutRedirected(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	os.Unsetenv("NO_COLOR")
	t.Setenv("FORCE_COLOR", "")
	os.Unsetenv("FORCE_COLOR")

	r, w, err := os.Pipe()
	require.NoError(t, err)

	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)
	cmd.SetOut(w)
	cmd.SetArgs([]string{"--format", "text"})

	require.NoError(t, cmd.Execute())
	require.NoError(t, w.Close())

	stdoutBytes, err := io.ReadAll(r)
	require.NoError(t, err)
	stdoutStr := string(stdoutBytes)

	assert.NotContains(t, stdoutStr, "\x1b[", "redirected pipe stdout must have zero ANSI escapes")
	assert.Contains(t, stdoutStr, "Version v3.1.0 is available.")
}
