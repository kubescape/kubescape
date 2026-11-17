package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lspHelperEnv = "KUBESCAPE_LSP_TEST_HELPER"

// TestLSPHelperProcess is not a test: the tests below run it in another process
// to run `kubescape lsp` as the real command, root command included, with its own
// standard output. It runs the command with the arguments after "--".
func TestLSPHelperProcess(t *testing.T) {
	if os.Getenv(lspHelperEnv) != "1" {
		t.Skip("only run as a helper process")
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	// What main does with the signals.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Args = append([]string{"kubescape"}, args...)
	if err := Execute(ctx, "test", "none", "unknown"); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(shared.ExitCode(err))
	}
	os.Exit(0)
}

// lockedBuffer is a buffer that the process's output can be copied into while the
// test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// lspProcess is `kubescape lsp` running, and a client for it.
type lspProcess struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *lockedBuffer
	nextID int
	done   chan error
}

func startLSP(t *testing.T, env []string, args ...string) *lspProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], //nolint:gosec // re-runs the test binary itself, with arguments built here
		append([]string{"-test.run=^TestLSPHelperProcess$", "--"}, append([]string{"lsp"}, args...)...)...)
	cmd.Env = append(os.Environ(), append([]string{
		lspHelperEnv + "=1",
		"KS_CACHE_DIR=" + t.TempDir(),
		// A scan that needs the network fails at once instead of reaching out.
		"HTTPS_PROXY=http://127.0.0.1:1", "HTTP_PROXY=http://127.0.0.1:1", "NO_PROXY=",
	}, env...)...)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	p := &lspProcess{t: t, cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: &lockedBuffer{}, done: make(chan error, 1)}
	cmd.Stderr = p.stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return p
}

func (p *lspProcess) send(msg map[string]any) {
	p.t.Helper()
	msg["jsonrpc"] = "2.0"
	b, err := json.Marshal(msg)
	require.NoError(p.t, err)
	_, err = fmt.Fprintf(p.stdin, "Content-Length: %d\r\n\r\n%s", len(b), b)
	require.NoError(p.t, err)
}

func (p *lspProcess) call(method string, params any) map[string]any {
	p.t.Helper()
	p.nextID++
	req := map[string]any{"id": p.nextID, "method": method}
	if params != nil {
		req["params"] = params
	}
	p.send(req)
	for {
		m := p.readFrame()
		if m["method"] == nil && fmt.Sprint(m["id"]) == strconv.Itoa(p.nextID) {
			return m
		}
	}
}

// readFrame reads a frame, and fails if what the process wrote to its standard
// output is anything but one.
func (p *lspProcess) readFrame() map[string]any {
	p.t.Helper()
	length := -1
	for {
		line, err := p.stdout.ReadString('\n')
		require.NoError(p.t, err, "standard output ended; stderr:\n%s", p.stderr.String())
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		require.True(p.t, ok && strings.HasPrefix(strings.ToLower(name), "content-"), "standard output holds something that is not an LSP header: %q", line)
		if strings.EqualFold(name, "Content-Length") {
			length, err = strconv.Atoi(strings.TrimSpace(value))
			require.NoError(p.t, err)
		}
	}
	require.GreaterOrEqual(p.t, length, 0, "a frame without Content-Length")
	body := make([]byte, length)
	_, err := io.ReadFull(p.stdout, body)
	require.NoError(p.t, err)
	var m map[string]any
	require.NoError(p.t, json.Unmarshal(body, &m), "a frame that is not JSON: %q", body)
	return m
}

// finish waits for the process to end and returns its exit code, after checking
// that nothing but frames is left on its standard output.
func (p *lspProcess) finish() int {
	p.t.Helper()
	go func() { p.done <- p.cmd.Wait() }()
	rest, _ := io.ReadAll(p.stdout)
	select {
	case err := <-p.done:
		assert.Empty(p.t, strings.TrimSpace(string(rest)), "unexpected output after the last frame")
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		p.t.Fatalf("waiting for the process: %v", err)
	case <-time.After(60 * time.Second):
		p.t.Fatal("the process did not end")
	}
	return -1
}

func (p *lspProcess) session(dir string) (uri string) {
	p.t.Helper()
	root := "file://" + filepath.ToSlash(dir)
	if !strings.HasPrefix(filepath.ToSlash(dir), "/") {
		root = "file:///" + filepath.ToSlash(dir)
	}
	res := p.call("initialize", map[string]any{"processId": nil, "rootUri": root, "capabilities": map[string]any{}})
	require.Nil(p.t, res["error"], "%v", res)
	p.send(map[string]any{"method": "initialized", "params": map[string]any{}})

	manifest := filepath.Join(dir, "pod.yaml")
	require.NoError(p.t, os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n  - name: c\n    image: nginx\n"), 0o600))
	uri = root + "/pod.yaml"
	p.send(map[string]any{"method": "textDocument/didOpen", "params": map[string]any{"textDocument": map[string]any{"uri": uri, "languageId": "yaml", "version": 1, "text": "x"}}})
	// A save starts a scan, which fails here for want of policies; the session must
	// go on, and its logs must not reach the protocol's channel.
	p.send(map[string]any{"method": "textDocument/didSave", "params": map[string]any{"textDocument": map[string]any{"uri": uri}}})
	return uri
}

// Standard output carries the protocol and nothing else, whatever logger is
// asked for. The slog (structured) logger writes JSON to standard output when left
// alone.
func TestLSPStandardOutputCarriesOnlyTheProtocol(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		args []string
	}{
		{name: "default logger"},
		{name: "slog (structured) logger from the environment", env: []string{"KS_LOGGER_NAME=slog"}},
		{name: "slog (structured) logger from the flag", args: []string{"--logger-name", "slog"}},
		{name: "debug level", env: []string{"KS_LOGGER_NAME=slog"}, args: []string{"--logger", "debug"}},
		{name: "icon logger", args: []string{"--logger-name", "icon"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := startLSP(t, tt.env, tt.args...)
			p.session(t.TempDir())
			require.Nil(t, p.call("shutdown", nil)["error"])
			p.send(map[string]any{"method": "exit"})
			assert.Equal(t, 0, p.finish())
			assert.Contains(t, p.stderr.String(), "language server", "the logs are on standard error")
		})
	}
}

func TestLSPExitWithoutShutdownIsExitCodeOne(t *testing.T) {
	p := startLSP(t, nil)
	res := p.call("initialize", map[string]any{"processId": nil, "rootUri": nil, "capabilities": map[string]any{}})
	require.Nil(t, res["error"])
	p.send(map[string]any{"method": "exit"})
	assert.Equal(t, 1, p.finish())
}

func TestLSPEndsOnSIGTERM(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("no SIGTERM on Windows")
	}
	p := startLSP(t, nil)
	require.Nil(t, p.call("initialize", map[string]any{"processId": nil, "rootUri": nil, "capabilities": map[string]any{}})["error"])
	require.NoError(t, p.cmd.Process.Signal(syscall.SIGTERM))
	assert.Equal(t, 1, p.finish(), "without a shutdown request")
}

func TestLSPRefusesArguments(t *testing.T) {
	p := startLSP(t, nil, "--transport", "tcp")
	assert.NotZero(t, p.finish(), "an unknown option is an error, not ignored")
	assert.Contains(t, p.stderr.String(), "unknown flag")
}
