package scan

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/mocks"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitLimit bounds every wait for something a test expects to happen, so that a
// test that fails fails and does not hang. A test never waits for it to pass.
const waitLimit = 60 * time.Second

func TestWatchFlagIsRegisteredOnTheScanCommandOnly(t *testing.T) {
	scanCmd := GetScanCommand(&mocks.MockIKubescape{})

	flag := scanCmd.Flags().Lookup("watch")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue, "a scan is not a watch unless it is asked to be")
	for _, sub := range scanCmd.Commands() {
		assert.Nil(t, sub.Flags().Lookup("watch"), "scan %s has no watch", sub.Name())
	}
}

func TestValidateWatchFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		flags   []string
		mutate  func(*cautils.ScanInfo)
		wantErr string
	}{
		{name: "a directory", args: []string{"./manifests"}},
		{name: "several inputs", args: []string{"a.yaml", "./manifests"}},
		{name: "the keep-local flag is fine", args: []string{"."}, flags: []string{"--keep-local"}},
		{name: "exclude paths are used", args: []string{"."}, flags: []string{"--exclude-path", "test/**"}},
		{name: "no input is a cluster", wantErr: "needs the files or directories"},
		{name: "standard input", args: []string{"-"}, wantErr: "standard input"},
		{name: "a format", args: []string{"."}, flags: []string{"--format", "json"}, wantErr: "--format cannot be used with --watch"},
		{name: "an output file", args: []string{"."}, flags: []string{"--output", "out.json"}, wantErr: "--output cannot be used with --watch"},
		{name: "a baseline", args: []string{"."}, flags: []string{"--baseline", "base.json"}, wantErr: "--baseline cannot be used with --watch"},
		{name: "a threshold", args: []string{"."}, flags: []string{"--severity-threshold", "high"}, wantErr: "--severity-threshold cannot be used with --watch"},
		{name: "image scanning", args: []string{"."}, flags: []string{"--scan-images"}, wantErr: "--scan-images cannot be used with --watch"},
		{name: "a kube context", args: []string{"."}, flags: []string{"--kube-contexts", "a,b"}, wantErr: "--kube-contexts cannot be used with --watch"},
		{name: "raw resources kept", args: []string{"."}, mutate: func(info *cautils.ScanInfo) { info.OmitRawResources = false }},
		{name: "raw resources omitted by the effective scan configuration", args: []string{"."}, mutate: func(info *cautils.ScanInfo) { info.OmitRawResources = true }, wantErr: "--omit-raw-resources cannot be used with --watch"},
		{name: "raw resources omitted by the flag", args: []string{"."}, flags: []string{"--omit-raw-resources"}, mutate: func(info *cautils.ScanInfo) { info.OmitRawResources = true }, wantErr: "--omit-raw-resources cannot be used with --watch"},
		{name: "raw resources explicitly kept by the flag", args: []string{"."}, flags: []string{"--omit-raw-resources=false"}},
		{name: "another view", args: []string{"."}, mutate: func(info *cautils.ScanInfo) { info.View = string(cautils.ControlViewType) }, wantErr: "--view"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanCmd := GetScanCommand(&mocks.MockIKubescape{})
			require.NoError(t, scanCmd.ParseFlags(tt.flags))
			info := &cautils.ScanInfo{View: string(cautils.SecurityViewType)}
			if tt.mutate != nil {
				tt.mutate(info)
			}

			err := validateWatchFlags(scanCmd, info, tt.args)

			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// An invocation --watch cannot serve is refused by the command, before anything
// is scanned, and the same invocation without it is as it was.
func TestScanWatchIsRefusedBeforeAnythingIsScanned(t *testing.T) {
	for name, args := range map[string][]string{
		"no input":  {"--watch"},
		"a format":  {t.TempDir(), "--watch", "--format", "json"},
		"an output": {t.TempDir(), "--watch", "--output", filepath.Join(t.TempDir(), "r.json")},
	} {
		t.Run(name, func(t *testing.T) {
			scanCmd := GetScanCommand(&mocks.MockIKubescape{})
			scanCmd.SetArgs(args)
			scanCmd.SetOut(&bytes.Buffer{})
			scanCmd.SetErr(&bytes.Buffer{})

			err := scanCmd.Execute()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "--watch")
		})
	}
}

// lines is a writer a test reads what a watch says from, a line at a time, so
// that it waits for what it expects and not for time to pass.
type lines struct {
	mu   sync.Mutex
	all  strings.Builder
	rest string
	feed chan string
}

func newLines() *lines { return &lines{feed: make(chan string, 4096)} }

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.all.Write(p)
	l.rest += string(p)
	for {
		i := strings.IndexByte(l.rest, '\n')
		if i < 0 {
			break
		}
		l.feed <- l.rest[:i]
		l.rest = l.rest[i+1:]
	}
	return len(p), nil
}

func (l *lines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.all.String()
}

// waitFor returns once a line that contains text has been written, and fails
// the test if none is.
func (l *lines) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.After(waitLimit)
	for {
		select {
		case line := <-l.feed:
			if strings.Contains(line, text) {
				return
			}
		case <-deadline:
			t.Fatalf("no line with %q was written; the output so far:\n%s", text, l.String())
		}
	}
}

var readOnlyRootFilesystem = cautils.BuildPolicyIdentifiers([]string{"C-0017"}, v1.KindControl)

func podManifest(name string, readOnly bool) string {
	manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\n  namespace: default\nspec:\n  containers:\n  - name: c\n    image: nginx\n"
	if readOnly {
		manifest += "    securityContext:\n      readOnlyRootFilesystem: true\n"
	}
	return manifest
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// localWatchScanInfo is the ScanInfo of a scan of dir that reads its policies
// from files in the repository, so that it needs no network.
func localWatchScanInfo(t *testing.T, paths ...string) *cautils.ScanInfo {
	t.Helper()
	abs := func(parts ...string) string {
		path, err := filepath.Abs(filepath.Join(parts...))
		require.NoError(t, err)
		return path
	}
	info := &cautils.ScanInfo{
		InputPatterns:  paths,
		UseFrom:        []string{abs("..", "..", "core", "cautils", "getter", "testdata", "NSA.json")},
		UseExceptions:  abs("..", "..", "core", "core", "testdata", "empty_exceptions.json"),
		ControlsInputs: abs("..", "..", "core", "cautils", "getter", "testdata", "controls-inputs.json"),
		View:           string(cautils.SecurityViewType),
	}
	info.SetScanType(cautils.ScanTypeControl)
	return info
}

// watching is a watch that runs for a test.
type watching struct {
	out, errOut *lines
	cancel      context.CancelFunc
	done        chan error
}

// startWatch runs a watch of the roots with the scan function, until the test
// stops it.
func startWatch(t *testing.T, roots []string, scan func(context.Context) (*watchScan, error)) *watching {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w := &watching{out: newLines(), errOut: newLines(), cancel: cancel, done: make(chan error, 1)}
	go func() {
		w.done <- runWatch(ctx, watchConfig{Roots: roots, Scan: scan, Debounce: 20 * time.Millisecond, Out: w.out, ErrOut: w.errOut})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-w.done:
		case <-time.After(waitLimit):
			t.Error("the watch did not stop")
		}
	})
	return w
}

// stop ends the watch and returns what it returned.
func (w *watching) stop(t *testing.T) error {
	t.Helper()
	w.cancel()
	select {
	case err := <-w.done:
		w.done <- err
		return err
	case <-time.After(waitLimit):
		t.Fatal("the watch did not stop")
		return nil
	}
}

// realScan scans paths with a LocalScanner, as the command does.
func realScan(t *testing.T, ks *core.Kubescape, paths ...string) func(context.Context) (*watchScan, error) {
	t.Helper()
	scanner, err := ks.NewLocalScanner(localWatchScanInfo(t, paths...), readOnlyRootFilesystem)
	require.NoError(t, err)
	return func(ctx context.Context) (*watchScan, error) {
		result, err := scanner.Scan(ctx, core.LocalInput{})
		if err != nil {
			return nil, err
		}
		return watchScanOf(result)
	}
}

// A watch scans at once, and again when a manifest changes, and says what each
// scan changed: a fixed finding is resolved, a new one is new.
func TestWatchReportsWhatEachChangeDid(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
	w := startWatch(t, []string{dir}, realScan(t, core.NewKubescape(context.Background()), dir))

	w.out.waitFor(t, "Initial scan complete")

	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", true))
	w.out.waitFor(t, "0 new, 1 resolved")

	writeFile(t, filepath.Join(dir, "second.yaml"), podManifest("api", false))
	w.out.waitFor(t, "1 new, 0 resolved")

	require.NoError(t, w.stop(t))
	assert.Contains(t, w.out.String(), "Watching "+dir)
	assert.Contains(t, w.out.String(), "Watch stopped.")
	assert.Empty(t, w.errOut.String())
}

// A scan that could not read a manifest is not a baseline, and what it did not
// see is not called fixed: a manifest that stops parsing takes its resource out of
// the scan, which is not the resource being fixed. The next scan that reads
// everything is compared with the baseline there was.
func TestWatchIncompleteScanDoesNotBecomeTheBaseline(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pod.yaml")
	writeFile(t, file, podManifest("web", false))
	writeFile(t, filepath.Join(dir, "other.yaml"), podManifest("api", true)) // a manifest that is read throughout
	w := startWatch(t, []string{dir}, realScan(t, core.NewKubescape(context.Background()), dir))
	w.out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")

	writeFile(t, file, "apiVersion: v1\nkind: [unclosed\n  - : :\n")
	w.out.waitFor(t, "Scan incomplete")
	assert.NotContains(t, w.out.String(), "1 resolved", "a resource the scan could not read is not a fixed one")
	assert.NotContains(t, w.out.String(), "1 removed", "nor is it one that was removed")

	writeFile(t, file, podManifest("web", false))
	w.out.waitFor(t, "No change in findings (1 existing)") // compared with the first scan, which is still the baseline
	require.NoError(t, w.stop(t))
}

// A scan that fails is reported and the watch goes on, with the baseline it had.
func TestWatchFailedScanKeepsTheBaseline(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
	ks := core.NewKubescape(context.Background())
	real := realScan(t, ks, dir)
	var scans atomic.Int32
	w := startWatch(t, []string{dir}, func(ctx context.Context) (*watchScan, error) {
		if scans.Add(1) == 2 {
			return nil, errors.New("the policies could not be loaded")
		}
		return real(ctx)
	})
	w.out.waitFor(t, "Initial scan complete")

	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", true))
	w.errOut.waitFor(t, "the policies could not be loaded")

	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", true))
	w.out.waitFor(t, "0 new, 1 resolved") // compared with the first scan, which is still the baseline
	require.NoError(t, w.stop(t))
}

// A first scan that fails is a watch that was set up wrong: it ends, with why.
func TestWatchEndsWhenTheInitialScanFails(t *testing.T) {
	dir := t.TempDir()
	boom := errors.New("the policies could not be loaded")
	w := startWatch(t, []string{dir}, func(context.Context) (*watchScan, error) { return nil, boom })

	select {
	case err := <-w.done:
		require.ErrorIs(t, err, boom)
		assert.Contains(t, err.Error(), "the initial scan failed")
		w.done <- err
	case <-time.After(waitLimit):
		t.Fatal("the watch went on")
	}
	assert.Contains(t, w.out.String(), "Watch stopped.")
}

// A change made while a scan runs is not lost, and many of them are not a scan
// each: the one scan that follows sees the last of them.
func TestWatchChangesDuringAScanAreScannedAfterIt(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pod.yaml")
	writeFile(t, file, "0")
	report := firstReport(t)

	var (
		mu       sync.Mutex
		scanned  []string
		started  = make(chan string, 64)
		release  = make(chan struct{})
		inScan   atomic.Int32
		overlaps atomic.Int32
	)
	w := startWatch(t, []string{dir}, func(ctx context.Context) (*watchScan, error) {
		if inScan.Add(1) > 1 {
			overlaps.Add(1)
		}
		defer inScan.Add(-1)
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		scanned = append(scanned, string(content))
		count := len(scanned)
		mu.Unlock()
		started <- string(content)
		if count == 2 {
			select { // the second scan is held while the files change
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &watchScan{ReportJSON: report}, nil
	})
	w.out.waitFor(t, "Initial scan complete")
	waitOn(t, w, started, "the first scan to start")

	writeFile(t, file, "1")
	require.Equal(t, "1", waitStarted(t, started))
	for i := 2; i <= 20; i++ {
		writeFile(t, file, string(rune('0'+i%10))+string(rune('a'+i)))
	}
	last := string(rune('0'+20%10)) + string(rune('a'+20))
	close(release)

	for got := ""; got != last; got = waitStarted(t, started) {
	}
	require.NoError(t, w.stop(t))

	mu.Lock()
	defer mu.Unlock()
	assert.LessOrEqual(t, len(scanned), 4, "twenty changes were not twenty scans: %v", scanned)
	assert.Equal(t, last, scanned[len(scanned)-1], "the last scan is of the latest state")
	assert.Zero(t, overlaps.Load(), "scans did not overlap")
}

func waitStarted(t *testing.T, started <-chan string) string {
	t.Helper()
	select {
	case content := <-started:
		return content
	case <-time.After(waitLimit):
		t.Fatal("no scan started")
		return ""
	}
}

// waitOn receives from a channel a test expects the watch to send on, and fails
// at once, with the reason, when the watch ends first, and when waitLimit passes:
// a watch that could not start is not waited for.
func waitOn[T any](t *testing.T, w *watching, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case err := <-w.done:
		w.done <- err
		t.Fatalf("the watch ended before %s: %v", what, err)
	case <-time.After(waitLimit):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

// firstReport is the report of a real scan of dir, for the tests whose scans are
// fakes that need a report a baseline can read.
func firstReport(t *testing.T) []byte {
	t.Helper()
	scratch := t.TempDir()
	writeFile(t, filepath.Join(scratch, "pod.yaml"), podManifest("web", false))
	scan, err := realScan(t, core.NewKubescape(context.Background()), scratch)(context.Background())
	require.NoError(t, err)
	return scan.ReportJSON
}

// The end of the context stops a scan that is running, and it is not reported as
// a failed scan or as a scan that found nothing.
func TestWatchCancellationDuringAScanStopsIt(t *testing.T) {
	dir := t.TempDir()
	inScan := make(chan struct{})
	var observedEnd atomic.Bool
	w := startWatch(t, []string{dir}, func(ctx context.Context) (*watchScan, error) {
		close(inScan)
		<-ctx.Done()
		observedEnd.Store(true)
		return nil, ctx.Err()
	})
	waitOn(t, w, inScan, "the scan to start")

	err := w.stop(t)

	require.NoError(t, err, "an interrupted watch is a watch that was stopped")
	assert.True(t, observedEnd.Load(), "the scan was cut short")
	assert.NotContains(t, w.out.String(), "Initial scan complete")
	assert.Empty(t, w.errOut.String(), "an interrupted scan is not a failed one")
	assert.Contains(t, w.out.String(), "Watch stopped.")
}

// Nothing a watch started outlives it.
func TestWatchReleasesWhatItStarted(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	writeFile(t, filepath.Join(first, "a.yaml"), "a")
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	scanned := make(chan struct{}, 8)
	go func() {
		done <- runWatch(ctx, watchConfig{
			Roots: []string{first, second},
			Scan: func(context.Context) (*watchScan, error) {
				scanned <- struct{}{}
				return nil, errors.New("not a real scan")
			},
			Out: &bytes.Buffer{}, ErrOut: &bytes.Buffer{},
		})
	}()
	select {
	case <-scanned:
	case err := <-done:
		select { // the scan reports it failed, which may end the watch before this looks
		case <-scanned:
			done <- err
		default:
			t.Fatalf("the watch ended before its first scan: %v", err)
		}
	case <-time.After(waitLimit):
		t.Fatal("timed out waiting for the first scan")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(waitLimit):
		t.Fatal("the watch did not stop")
	}

	assert.True(t, settles(before), "goroutines before %d, after %d", before, runtime.NumGoroutine())
}

// settles polls, and not sleeps for a time chosen in advance, until the number of
// goroutines is back to what it was: goroutines that are ending take a moment.
func settles(want int) bool {
	deadline := time.Now().Add(waitLimit)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= want {
			return true
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	return runtime.NumGoroutine() <= want
}

// A watcher that cannot go on ends the watch, with its reason: a watch that
// cannot see changes is not left running.
func TestWatchEndsWhenTheWatcherDoes(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "manifests")
	require.NoError(t, os.Mkdir(dir, 0o700))
	report := firstReport(t)
	w := startWatch(t, []string{dir}, func(context.Context) (*watchScan, error) { return &watchScan{ReportJSON: report}, nil })
	w.out.waitFor(t, "Initial scan complete")

	require.NoError(t, os.RemoveAll(dir))

	select {
	case err := <-w.done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "the watch ended")
		assert.Contains(t, err.Error(), "removed or renamed")
		w.done <- err
	case <-time.After(waitLimit):
		t.Fatal("the watch went on without a directory")
	}
}

func TestWatchRefusesARootThatCannotBeWatched(t *testing.T) {
	var scans atomic.Int32
	err := runWatch(context.Background(), watchConfig{
		Roots: []string{filepath.Join(t.TempDir(), "missing")},
		Scan:  func(context.Context) (*watchScan, error) { scans.Add(1); return nil, nil },
		Out:   &bytes.Buffer{}, ErrOut: &bytes.Buffer{},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--watch")
	assert.Zero(t, scans.Load(), "nothing was scanned")
}

// More than one input is watched, and a change in any of them is a scan.
func TestWatchWatchesEveryInput(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	report := firstReport(t)
	scans := make(chan struct{}, 16)
	w := startWatch(t, []string{first, second}, func(context.Context) (*watchScan, error) {
		scans <- struct{}{}
		return &watchScan{ReportJSON: report}, nil
	})
	waitOn(t, w, scans, "the first scan")

	writeFile(t, filepath.Join(second, "pod.yaml"), podManifest("web", false))

	select {
	case <-scans:
	case <-time.After(waitLimit):
		t.Fatal("a change in the second input was not scanned")
	}
	require.NoError(t, w.stop(t))
}

// The command's own wiring: a watch of a directory, through the LocalScanner,
// with no reach for the cluster the kubeconfig names.
func TestWatchSecurityScanDoesNotContactTheCluster(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	writeFile(t, kubeconfig, `apiVersion: v1
kind: Config
clusters:
- cluster: {server: "`+server.URL+`", insecure-skip-tls-verify: true}
  name: fake
contexts:
- context: {cluster: fake, user: u}
  name: fake
current-context: fake
users:
- name: u
  user: {token: x}
`)
	t.Setenv("KUBECONFIG", kubeconfig)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
	ctx, cancel := context.WithCancel(context.Background())
	ks := core.NewKubescape(ctx)
	out := newLines()
	scanCmd := &cobra.Command{}
	scanCmd.SetOut(out)
	scanCmd.SetErr(&bytes.Buffer{})
	done := make(chan error, 1)
	go func() {
		done <- watchSecurityScan(scanCmd, ks, localWatchScanInfo(t, dir), readOnlyRootFilesystem)
	}()

	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(waitLimit):
		t.Fatal("the watch did not stop")
	}
	assert.Zero(t, requests.Load(), "the watch did not reach for the cluster")
}

// startSecurityWatch runs the command's own wiring, watchSecurityScan, over
// inputs until the test stops it. stop ends it and returns what it returned.
func startSecurityWatch(t *testing.T, info *cautils.ScanInfo) (out *lines, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ks := core.NewKubescape(ctx)
	out = newLines()
	scanCmd := &cobra.Command{}
	scanCmd.SetOut(out)
	scanCmd.SetErr(&bytes.Buffer{})
	done := make(chan error, 1)
	go func() { done <- watchSecurityScan(scanCmd, ks, info, readOnlyRootFilesystem) }()
	stop = func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(waitLimit):
			t.Fatal("the watch did not stop")
			return nil
		}
	}
	t.Cleanup(func() { cancel() })
	return out, stop
}

// An input that is a glob is watched through the directory the scanner lists it
// from, and is scanned as the scanner expands it.
func TestWatchSecurityScanWatchesGlobInputs(t *testing.T) {
	t.Run("a glob of files", func(t *testing.T) {
		dir := t.TempDir()
		manifests := filepath.Join(dir, "manifests")
		writeFile(t, filepath.Join(manifests, "pod.yaml"), podManifest("web", false))
		info := localWatchScanInfo(t, "./manifests/*.yaml") // as typed, relative to where the command runs
		t.Chdir(dir)
		out, stop := startSecurityWatch(t, info)

		out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
		writeFile(t, filepath.Join(manifests, "pod.yaml"), podManifest("web", true))
		out.waitFor(t, "0 new, 1 resolved")
		writeFile(t, filepath.Join(manifests, "second.yaml"), podManifest("api", false))
		out.waitFor(t, "1 new, 0 resolved")

		require.NoError(t, stop())
		assert.Contains(t, out.String(), "Watching manifests")
	})

	t.Run("a glob matches below its directory, as the scanner lists it", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "team", "prod", "pod.yaml")
		writeFile(t, file, podManifest("web", false))
		out, stop := startSecurityWatch(t, localWatchScanInfo(t, filepath.Join(dir, "*.yaml")))

		out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
		writeFile(t, file, podManifest("web", true))
		out.waitFor(t, "0 new, 1 resolved")

		require.NoError(t, stop())
		assert.Contains(t, out.String(), "Watching "+dir)
	})

	t.Run("several inputs in different directories", func(t *testing.T) {
		first, second := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(first, "pod.yaml"), podManifest("web", false))
		writeFile(t, filepath.Join(second, "api.yaml"), podManifest("api", false))
		out, stop := startSecurityWatch(t, localWatchScanInfo(t, filepath.Join(first, "*.yaml"), filepath.Join(second, "*.yaml")))

		out.waitFor(t, "Initial scan complete: 1 failing control(s) on 2 resource(s)")
		writeFile(t, filepath.Join(second, "api.yaml"), podManifest("api", true))
		out.waitFor(t, "0 new, 1 resolved")

		require.NoError(t, stop())
	})
}

// A kustomization given as the input is rendered with the resources it lists, so
// a change to one of them is a change to the input.
func TestWatchSecurityScanWatchesWhatAKustomizationInputRenders(t *testing.T) {
	dir := t.TempDir()
	kustomization := filepath.Join(dir, "kustomization.yaml")
	writeFile(t, kustomization, "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- pod.yaml\n")
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
	out, stop := startSecurityWatch(t, localWatchScanInfo(t, kustomization))

	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", true))
	out.waitFor(t, "0 new, 1 resolved")

	require.NoError(t, stop())
}

func TestWatchSecurityScanWatchesSharedKustomizeBase(t *testing.T) {
	for _, name := range []string{"outside the scan root", "excluded from the scan"} {
		t.Run(name, func(t *testing.T) {
			repo := t.TempDir()
			overlay := filepath.Join(repo, "overlay")
			base := filepath.Join(repo, "base")
			pod := filepath.Join(base, "pod.yaml")
			const kustomization = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: "
			writeFile(t, filepath.Join(overlay, "kustomization.yaml"), kustomization+"[../base]\n")
			writeFile(t, filepath.Join(base, "kustomization.yaml"), kustomization+"[pod.yaml]\n")
			writeFile(t, pod, podManifest("web", false))
			root := overlay
			if name == "excluded from the scan" {
				root = repo
				writeFile(t, filepath.Join(repo, cautils.IgnoreFileName), "base/\n")
			}

			out, stop := startSecurityWatch(t, localWatchScanInfo(t, root))
			out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
			out.waitFor(t, "No change in findings")
			writeFile(t, pod, podManifest("web", true))
			out.waitFor(t, "0 new, 1 resolved")
			require.NoError(t, stop())
		})
	}
}

func TestWatchSecurityScanFollowsChangedKustomizeBase(t *testing.T) {
	repo := t.TempDir()
	overlay := filepath.Join(repo, "overlay", "kustomization.yaml")
	first := filepath.Join(repo, "first")
	second := filepath.Join(repo, "second")
	const kustomization = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: "
	writeFile(t, overlay, kustomization+"[../first]\n")
	writeFile(t, filepath.Join(first, "kustomization.yaml"), kustomization+"[pod.yaml]\n")
	writeFile(t, filepath.Join(first, "pod.yaml"), podManifest("web", false))
	writeFile(t, filepath.Join(second, "kustomization.yaml"), kustomization+"[pod.yaml]\n")
	pod := filepath.Join(second, "pod.yaml")
	writeFile(t, pod, podManifest("web", true))

	out, stop := startSecurityWatch(t, localWatchScanInfo(t, overlay))
	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	out.waitFor(t, "No change in findings")
	writeFile(t, overlay, kustomization+"[../second]\n")
	out.waitFor(t, "0 new, 1 resolved")
	out.waitFor(t, "No change in findings")

	// Editors often replace the dependency by renaming a temporary file.
	replacement := filepath.Join(second, "pod.tmp")
	writeFile(t, replacement, podManifest("web", false))
	require.NoError(t, os.Rename(replacement, pod))
	out.waitFor(t, "1 new, 0 resolved")
	require.NoError(t, stop())
}

func TestWatchSecurityScanRecoversWhenSharedKustomizeBaseAppears(t *testing.T) {
	repo := t.TempDir()
	overlay := filepath.Join(repo, "overlay")
	base := filepath.Join(repo, "base")
	const kustomization = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: "
	writeFile(t, filepath.Join(overlay, "kustomization.yaml"), kustomization+"[../base]\n")

	out, stop := startSecurityWatchOutput(t, localWatchScanInfo(t, overlay))
	out.waitFor(t, "the watch waits for a change")
	out.waitFor(t, "Scan failed")
	require.NoError(t, os.Mkdir(base, 0o750))
	out.waitFor(t, "Change detected, scanning again...")
	writeFile(t, filepath.Join(base, "kustomization.yaml"), kustomization+"[pod.yaml]\n")
	writeFile(t, filepath.Join(base, "pod.yaml"), podManifest("web", false))
	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	require.NoError(t, stop())
}

func TestWatchSecurityScanFollowsDirectoryLinksInSharedBase(t *testing.T) {
	for _, name := range []string{"retargeted link", "chained link", "broken link", "dangling target", "file instead of target directory"} {
		t.Run(name, func(t *testing.T) {
			blocked := name == "file instead of target directory"
			missing := name == "dangling target" || blocked
			broken := name == "broken link" || missing
			overlay, base := sharedKustomizeWatchFixture(t, "resources: [current/pod.yaml]\n")
			writeFile(t, filepath.Join(base, "old", "pod.yaml"), podManifest("web", false))
			writeFile(t, filepath.Join(base, "new", "pod.yaml"), podManifest("web", !broken))
			link := filepath.Join(base, "current")
			target := "old"
			switch name {
			case "broken link":
				target = "current"
			case "dangling target", "file instead of target directory":
				target = "missing"
			}
			if blocked {
				writeFile(t, filepath.Join(base, target), "not a directory")
			}
			if err := os.Symlink(target, link); err != nil && runtime.GOOS == "windows" {
				t.Skipf("directory symlink unavailable: %v", err)
			} else {
				require.NoError(t, err)
			}
			if name == "chained link" {
				require.NoError(t, os.Rename(link, filepath.Join(base, "slot")))
				require.NoError(t, os.Symlink("slot", link))
				link = filepath.Join(base, "slot")
			}

			out, stop := startSecurityWatchOutput(t, localWatchScanInfo(t, overlay))
			const initial = "Initial scan complete: 1 failing control(s) on 1 resource(s)"
			if broken {
				out.waitFor(t, "the watch waits for a change")
				out.waitFor(t, "Scan failed")
			} else {
				out.waitFor(t, initial)
				out.waitFor(t, "No change in findings")
			}
			if missing {
				if blocked {
					require.NoError(t, os.Remove(filepath.Join(base, target)))
				}
				writeFile(t, filepath.Join(base, "missing", "pod.yaml"), podManifest("web", false))
			} else {
				replacement := filepath.Join(base, "replacement")
				require.NoError(t, os.Symlink("new", replacement))
				require.NoError(t, os.Rename(replacement, link))
			}
			if broken {
				out.waitFor(t, initial)
			} else {
				out.waitFor(t, "0 new, 1 resolved")
			}
			require.NoError(t, stop())
		})
	}
}

func TestWatchSecurityScanKeepsSharedBaseWatchAfterPolicyError(t *testing.T) {
	overlay, base := sharedKustomizeWatchFixture(t, "resources: [pod.yaml]\n")
	pod := filepath.Join(base, "pod.yaml")
	writeFile(t, pod, podManifest("web", false))
	info := localWatchScanInfo(t, overlay)
	policy, err := os.ReadFile(info.UseFrom[0])
	require.NoError(t, err)
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writeFile(t, policyPath, string(policy))
	info.UseFrom = []string{policyPath}

	out, stop := startSecurityWatchOutput(t, info)
	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	out.waitFor(t, "No change in findings")
	writeFile(t, policyPath, "invalid policy")
	config := filepath.Join(overlay, "kustomization.yaml")
	before, err := os.ReadFile(config)
	require.NoError(t, err)
	writeFile(t, config, string(before)+"# trigger a rescan\n")
	out.waitFor(t, "Scan failed")
	writeFile(t, policyPath, string(policy))
	writeFile(t, pod, podManifest("web", true))
	out.waitFor(t, "0 new, 1 resolved")
	require.NoError(t, stop())
}

func TestWatchSecurityScanKeepsDependenciesAcrossFailedRenders(t *testing.T) {
	overlay, base := sharedKustomizeWatchFixture(t, "resources: [pod.yaml]\n")
	writeFile(t, filepath.Join(base, "pod.yaml"), podManifest("web", false))
	repo := filepath.Dir(overlay)
	second, third := filepath.Join(repo, "second"), filepath.Join(repo, "third")
	const config = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: "
	for _, dir := range []string{second, third} {
		writeFile(t, filepath.Join(dir, "kustomization.yaml"), config+"[pod.yaml]\n")
		writeFile(t, filepath.Join(dir, "pod.yaml"), "kind: [broken\n")
	}

	out, stop := startSecurityWatchOutput(t, localWatchScanInfo(t, overlay))
	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	out.waitFor(t, "No change in findings")
	for _, resources := range []string{"[../second]", "[../third, ../second]"} {
		writeFile(t, filepath.Join(overlay, "kustomization.yaml"), config+resources+"\n")
		out.waitFor(t, "Scan failed:")
		out.waitFor(t, "Scan failed:") // catch up after adding the new dependency
	}

	// The last render failed in third before it reached second.
	writeFile(t, filepath.Join(second, "pod.yaml"), podManifest("web", true))
	out.waitFor(t, "Scan failed:") // the edit requests a fresh scan
	require.NoError(t, stop())
}

func TestWatchSecurityScanWatchesSharedBaseWithDifferentFilenameCase(t *testing.T) {
	overlay, base := sharedKustomizeWatchFixture(t, "resources: [pod.yaml]\n")
	pod := filepath.Join(base, "Pod.yaml")
	writeFile(t, pod, podManifest("web", false))
	if _, err := os.Stat(filepath.Join(base, "pod.yaml")); errors.Is(err, os.ErrNotExist) {
		t.Skip("the test filesystem is case-sensitive")
	} else {
		require.NoError(t, err)
	}
	out, stop := startSecurityWatch(t, localWatchScanInfo(t, overlay))
	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	out.waitFor(t, "No change in findings")
	writeFile(t, pod, podManifest("web", true))
	out.waitFor(t, "0 new, 1 resolved")
	require.NoError(t, stop())
}

func TestWatchSecurityScanWatchesHelmTemplatesInSharedBase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Helm stub uses a POSIX shell")
	}
	bin := t.TempDir()
	helm := filepath.Join(bin, "helm")
	writeFile(t, helm, "#!/bin/sh\ncase \"$1\" in\n  version) printf '%s\\n' 'v3.19.0' ;;\n  template) /bin/cat \"$3/templates/pod.yaml\" ;;\n  *) exit 1 ;;\nesac\n")
	require.NoError(t, os.Chmod(helm, 0o700))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	for _, name := range []string{"helmCharts", "builtin generator", "linked kustomization", "broken template"} {
		t.Run(name, func(t *testing.T) {
			config := "helmCharts:\n- name: web\n  releaseName: web\n"
			if name == "builtin generator" {
				config = "generators: [chart-generator.yaml]\n"
			}
			overlay, base := sharedKustomizeWatchFixture(t, config)
			switch name {
			case "builtin generator":
				writeFile(t, filepath.Join(base, "chart-generator.yaml"), "apiVersion: builtin\nkind: HelmChartInflationGenerator\nmetadata:\n  name: web\nname: web\nreleaseName: web\n")
			case "linked kustomization":
				require.NoError(t, os.Mkdir(filepath.Join(base, "configs"), 0o750))
				require.NoError(t, os.Rename(filepath.Join(base, "kustomization.yaml"), filepath.Join(base, "configs", "kustomization.yaml")))
				require.NoError(t, os.Symlink("configs/kustomization.yaml", filepath.Join(base, "kustomization.yaml")))
			}
			chart := filepath.Join(base, "charts", "web")
			writeFile(t, filepath.Join(chart, "Chart.yaml"), "apiVersion: v2\nname: web\nversion: 0.1.0\n")
			writeFile(t, filepath.Join(chart, "values.yaml"), "{}\n")
			template := filepath.Join(chart, "templates", "pod.yaml")
			broken := name == "broken template"
			if broken {
				writeFile(t, template, "kind: [broken\n")
			} else {
				writeFile(t, template, podManifest("web", false))
			}
			out, stop := startSecurityWatchOutput(t, localWatchScanInfo(t, overlay))
			const initial = "Initial scan complete: 1 failing control(s) on 1 resource(s)"
			if broken {
				out.waitFor(t, "the watch waits for a change")
				out.waitFor(t, "Scan failed")
				writeFile(t, template, podManifest("web", false))
				out.waitFor(t, initial)
			} else {
				out.waitFor(t, initial)
				out.waitFor(t, "No change in findings")
				writeFile(t, template, podManifest("web", true))
				out.waitFor(t, "0 new, 1 resolved")
			}
			require.NoError(t, stop())
		})
	}
}

func sharedKustomizeWatchFixture(t *testing.T, baseConfig string) (overlay, base string) {
	t.Helper()
	repo := t.TempDir()
	overlay, base = filepath.Join(repo, "overlay"), filepath.Join(repo, "base")
	const header = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
	writeFile(t, filepath.Join(overlay, "kustomization.yaml"), header+"resources: [../base]\n")
	writeFile(t, filepath.Join(base, "kustomization.yaml"), header+baseConfig)
	return overlay, base
}

// The kustomization itself is watched as well when its directory is: kustomize
// also accepts it under the extensionless name Kustomization, and an edit to it
// is an edit to the input.
func TestWatchSecurityScanWatchesAnExtensionlessKustomization(t *testing.T) {
	dir := t.TempDir()
	kustomization := filepath.Join(dir, "Kustomization")
	writeFile(t, kustomization, "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- pod.yaml\n")
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
	writeFile(t, filepath.Join(dir, "api.yaml"), podManifest("api", false))
	out, stop := startSecurityWatch(t, localWatchScanInfo(t, kustomization))

	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	writeFile(t, kustomization, "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- pod.yaml\n- api.yaml\n")
	out.waitFor(t, "1 new, 0 resolved")

	require.NoError(t, stop())
}

// A directory that gains a kustomization is rendered with the files it lists,
// even extensionless ones, so an edit to such a dependency made after the
// kustomization appeared must trigger a rescan.
func TestWatchSecurityScanFollowsAKustomizationThatAppears(t *testing.T) {
	dir := t.TempDir()
	kustomization := filepath.Join(dir, "kustomization.yaml")
	patch := filepath.Join(dir, "security")
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
	writeFile(t, patch, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n  - name: c\n    image: nginx\n    securityContext:\n      readOnlyRootFilesystem: true\n")
	out, stop := startSecurityWatch(t, localWatchScanInfo(t, dir))

	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	writeFile(t, kustomization, "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- pod.yaml\npatches:\n- path: security\n  target:\n    kind: Pod\n    name: web\n")
	out.waitFor(t, "0 new, 1 resolved")

	writeFile(t, patch, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n  - name: c\n    image: nginx\n")
	out.waitFor(t, "1 new, 0 resolved")

	require.NoError(t, stop())
}

// A kustomization input is also rendered with the patch files it lists (e.g.
// patches/security.patch), and an edit to a patch file must trigger a rescan.
func TestWatchSecurityScanWatchesWhatAKustomizationPatchRenders(t *testing.T) {
	dir := t.TempDir()
	kustomization := filepath.Join(dir, "kustomization.yaml")
	patch := filepath.Join(dir, "security.patch")
	writeFile(t, kustomization, "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- pod.yaml\npatches:\n- path: security.patch\n  target:\n    kind: Pod\n    name: web\n")
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
	writeFile(t, patch, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n  - name: c\n    image: nginx\n")
	out, stop := startSecurityWatch(t, localWatchScanInfo(t, kustomization))

	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	writeFile(t, patch, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n  - name: c\n    image: nginx\n    securityContext:\n      readOnlyRootFilesystem: true\n")
	out.waitFor(t, "0 new, 1 resolved")

	require.NoError(t, stop())
}

// A directory scan renders the kustomizations below it as well, so the files
// such a kustomization reads, an extensionless patch among them, are watched
// as dependencies, not only those of a kustomization at the root.
func TestWatchSecurityScanWatchesANestedKustomizationsDependencies(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "app")
	patch := filepath.Join(app, "security")
	writeFile(t, filepath.Join(app, "pod.yaml"), podManifest("web", false))
	writeFile(t, patch, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n  - name: c\n    image: nginx\n    securityContext:\n      readOnlyRootFilesystem: true\n")
	writeFile(t, filepath.Join(app, "kustomization.yaml"), "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- pod.yaml\npatches:\n- path: security\n  target:\n    kind: Pod\n    name: web\n")
	out, stop := startSecurityWatch(t, localWatchScanInfo(t, dir))

	out.waitFor(t, "Initial scan complete: 0 failing control(s) on 0 resource(s)")
	writeFile(t, patch, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n  - name: c\n    image: nginx\n")
	out.waitFor(t, "Change detected, scanning again...")
	out.waitFor(t, "1 new, 0 resolved")

	require.NoError(t, stop())
}

// A directory scan renders the Helm charts below it, and a chart's templates
// read the chart's own files through .Files whatever their extension, so an
// edit to such a file is an edit to what is scanned and must trigger a rescan.
func TestWatchSecurityScanWatchesWhatAHelmChartReads(t *testing.T) {
	dir := t.TempDir()
	chart := filepath.Join(dir, "app")
	security := filepath.Join(chart, "files", "security")
	writeFile(t, filepath.Join(chart, "Chart.yaml"), "apiVersion: v2\nname: app\nversion: 0.1.0\n")
	writeFile(t, filepath.Join(chart, "templates", "pod.yaml"), "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n  namespace: default\nspec:\n  containers:\n  - name: c\n    image: nginx\n{{ .Files.Get \"files/security\" | indent 4 }}\n")
	writeFile(t, security, "securityContext:\n  readOnlyRootFilesystem: true\n")
	out, stop := startSecurityWatch(t, localWatchScanInfo(t, dir))

	out.waitFor(t, "Initial scan complete: 0 failing control(s) on 0 resource(s)")
	writeFile(t, security, "securityContext: {}\n")
	out.waitFor(t, "Change detected, scanning again...")
	out.waitFor(t, "1 new, 0 resolved")

	require.NoError(t, stop())
}

func TestInHelmChartBelow(t *testing.T) {
	root := t.TempDir()
	chart := filepath.Join(root, "app")
	writeFile(t, filepath.Join(chart, "Chart.yaml"), "apiVersion: v2\nname: app\nversion: 0.1.0\n")
	require.NoError(t, os.MkdirAll(filepath.Join(chart, "files"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(chart, "charts"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "other"), 0o700))

	assert.True(t, inHelmChartBelow(root, filepath.Join(chart, ".helmignore")), "in a chart's directory")
	assert.True(t, inHelmChartBelow(root, filepath.Join(chart, "files", "nginx.conf")), "a file the templates read through .Files")
	assert.True(t, inHelmChartBelow(root, filepath.Join(chart, "charts", "redis-1.2.3.tgz")), "a vendored subchart archive")
	assert.False(t, inHelmChartBelow(root, filepath.Join(root, "other", "nginx.conf")), "beside a chart")
	assert.False(t, inHelmChartBelow(root, filepath.Join(root, "nginx.conf")), "above a chart")

	// A chart above the watch root is not rendered by a scan of the root, so it
	// must not make every file of the root a dependency.
	inner := filepath.Join(chart, "files")
	assert.False(t, inHelmChartBelow(inner, filepath.Join(inner, "nginx.conf")), "a chart above the watch root")
}

func TestInKustomizationBelow(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "app")
	writeFile(t, filepath.Join(app, "kustomization.yaml"), "resources: []\n")
	require.NoError(t, os.MkdirAll(filepath.Join(app, "patches"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "other"), 0o700))

	assert.True(t, inKustomizationBelow(root, filepath.Join(app, "security")), "in a kustomization's directory")
	assert.True(t, inKustomizationBelow(root, filepath.Join(app, "patches", "security")), "below one")
	assert.False(t, inKustomizationBelow(root, filepath.Join(root, "other", "security")), "beside one")
	assert.False(t, inKustomizationBelow(root, filepath.Join(root, "security")), "above one")
}
func TestInKustomizationBelowWithRelativeRoot(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	base, err := os.MkdirTemp(cwd, "kustomization-watch-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(base))
	})

	root := filepath.Join(base, "manifests")
	app := filepath.Join(root, "app")

	require.NoError(t, os.MkdirAll(app, 0o700))

	// This Kustomization is above the watched root and must not
	// cause unrelated files inside the watched root to be accepted.
	writeFile(t, filepath.Join(base, "kustomization.yaml"), "resources: []\n")

	// A Kustomization inside the watched root must still be accepted.
	writeFile(t, filepath.Join(app, "kustomization.yaml"), "resources: []\n")

	relativeRoot, err := filepath.Rel(cwd, root)
	require.NoError(t, err)

	assert.False(
		t,
		inKustomizationBelow(relativeRoot, filepath.Join(root, "notes.txt")),
		"a kustomization above the relative watch root must not be accepted",
	)

	assert.True(
		t,
		inKustomizationBelow(relativeRoot, filepath.Join(app, "security")),
		"a kustomization inside the relative watch root must still be accepted",
	)
}

func TestWatchRoots(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pod.yaml")
	writeFile(t, file, podManifest("web", false))

	tests := []struct {
		name   string
		inputs []string
		want   []string
	}{
		{name: "a file is watched as it is", inputs: []string{file}, want: []string{file}},
		{name: "a directory is watched as it is", inputs: []string{dir}, want: []string{dir}},
		{name: "a glob is watched through the directory it lists", inputs: []string{filepath.Join(dir, "*.yaml")}, want: []string{dir}},
		{name: "a nested glob is watched through its literal prefix", inputs: []string{filepath.Join(dir, "*", "prod", "*.yaml")}, want: []string{dir}},
		{name: "a shared directory is watched once", inputs: []string{filepath.Join(dir, "*.yaml"), filepath.Join(dir, "*.json"), dir}, want: []string{dir}},
		{name: "inputs in different directories are all watched", inputs: []string{file, filepath.Join(dir, "sub", "*.yaml")}, want: []string{file, filepath.Join(dir, "sub")}},
		{name: "a kustomization is watched through its directory", inputs: []string{filepath.Join(dir, "overlay", "kustomization.yaml")}, want: []string{filepath.Join(dir, "overlay")}},
		{name: "a Terraform file is watched through its directory", inputs: []string{filepath.Join(dir, "infra", "main.tf")}, want: []string{filepath.Join(dir, "infra")}},
		{name: "a kustomization next to a watched directory is watched once", inputs: []string{dir, filepath.Join(dir, "kustomization.yaml")}, want: []string{dir}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, watchRoots(tt.inputs))
		})
	}
}

// The scan reads .kubescapeignore on every run, so the watch follows it: an edit
// to it is scanned, and a directory it no longer excludes is watched.
func TestWatchSecurityScanFollowsTheIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, cautils.IgnoreFileName), "extra/\n")
	writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
	writeFile(t, filepath.Join(dir, "extra", "api.yaml"), podManifest("api", false))
	out, stop := startSecurityWatch(t, localWatchScanInfo(t, dir))
	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")

	writeFile(t, filepath.Join(dir, cautils.IgnoreFileName), "# nothing excluded\n")
	out.waitFor(t, "1 new, 0 resolved") // the scan now reads extra/api.yaml

	writeFile(t, filepath.Join(dir, "extra", "api.yaml"), podManifest("api", true))
	out.waitFor(t, "0 new, 1 resolved") // and a change in extra/ is seen

	require.NoError(t, stop())
}

// A first scan that fails on its input (no manifest yet, one that does not parse, no
// Kubernetes object yet) is mended by an edit to a manifest, so it does not end the
// watch: the first scan that succeeds after the edit is the initial one.
func TestWatchOutlivesAnInitialScanThatAManifestEditMends(t *testing.T) {
	for name, content := range map[string]string{
		"no manifest yet":                  "",
		"the only manifest does not parse": "apiVersion: v1\nkind: [unclosed\n  - : :\n",
		"no Kubernetes object yet":         "todo: write the pod\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if content != "" {
				writeFile(t, filepath.Join(dir, "pod.yaml"), content)
			}
			out, stop := startSecurityWatchOutput(t, localWatchScanInfo(t, dir))

			out.waitFor(t, "the watch waits for a change")
			writeFile(t, filepath.Join(dir, "pod.yaml"), podManifest("web", false))
			out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
			require.NoError(t, stop())
		})
	}
}

func TestWatchRecoversFromInvalidKustomizeResource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- pod.yaml
`)
	pod := filepath.Join(dir, "pod.yaml")
	writeFile(t, pod, "apiVersion: v1\nkind: [unclosed\n")
	out, stop := startSecurityWatchOutput(t, localWatchScanInfo(t, dir))

	out.waitFor(t, "the watch waits for a change")
	writeFile(t, pod, podManifest("web", false))
	out.waitFor(t, "Initial scan complete: 1 failing control(s) on 1 resource(s)")
	writeFile(t, pod, podManifest("web", true))
	out.waitFor(t, "0 new, 1 resolved")
	require.NoError(t, stop())
}

// startSecurityWatchOutput is startSecurityWatch with the command's error output
// written to the same lines as its output.
func startSecurityWatchOutput(t *testing.T, info *cautils.ScanInfo) (out *lines, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ks := core.NewKubescape(ctx)
	out = newLines()
	scanCmd := &cobra.Command{}
	scanCmd.SetOut(out)
	scanCmd.SetErr(out)
	done := make(chan error, 1)
	go func() { done <- watchSecurityScan(scanCmd, ks, info, readOnlyRootFilesystem) }()
	stop = func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(waitLimit):
			t.Fatal("the watch did not stop")
			return nil
		}
	}
	t.Cleanup(func() { cancel() })
	return out, stop
}

func TestReloadingFilterDetectsContentChangeWithUnchangedMetadata(t *testing.T) {
	dir := t.TempDir()
	ignoreFile := filepath.Join(dir, cautils.IgnoreFileName)
	writeFile(t, ignoreFile, "first/\n")
	info, err := os.Stat(ignoreFile)
	require.NoError(t, err)
	filter, err := newReloadingFilter(dir, nil, true)
	require.NoError(t, err)
	first := filepath.Join(dir, "first")
	other := filepath.Join(dir, "other")
	require.True(t, filter.Excluded(first, true))
	require.False(t, filter.Excluded(other, true))

	writeFile(t, ignoreFile, "other/\n")
	require.NoError(t, os.Chtimes(ignoreFile, info.ModTime(), info.ModTime()))
	updated, err := os.Stat(ignoreFile)
	require.NoError(t, err)
	require.Equal(t, info.Size(), updated.Size())
	require.True(t, info.ModTime().Equal(updated.ModTime()))

	assert.False(t, filter.Excluded(first, true), "a newly included directory must be watched")
	assert.True(t, filter.Excluded(other, true), "the new exclusion must replace the previous one")
}

func TestReloadingFilterRetainsRulesOnReadErrorAndRecovers(t *testing.T) {
	dir := t.TempDir()
	ignoreFile := filepath.Join(dir, cautils.IgnoreFileName)
	writeFile(t, ignoreFile, "first/\n")
	filter, err := newReloadingFilter(dir, nil, true)
	require.NoError(t, err)
	first := filepath.Join(dir, "first")
	require.True(t, filter.Excluded(first, true))

	// An unreadable ignore file must not clear the previous exclusions.
	require.NoError(t, os.Remove(ignoreFile))
	require.NoError(t, os.Mkdir(ignoreFile, 0o700))
	assert.True(t, filter.Excluded(first, true))
	require.NoError(t, os.Remove(ignoreFile))
	writeFile(t, ignoreFile, "other/\n")
	assert.False(t, filter.Excluded(first, true))
	assert.True(t, filter.Excluded(filepath.Join(dir, "other"), true))

	// Removing the ignore file restores the empty rule set.
	require.NoError(t, os.Remove(ignoreFile))
	assert.False(t, filter.Excluded(filepath.Join(dir, "other"), true))
}
