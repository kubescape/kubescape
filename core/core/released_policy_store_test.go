package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// regolibraryReleases stands in for the regolibrary releases on GitHub, which is
// where a scan without policy files downloads its policies from. It serves two
// releases: "v2", the latest, which holds every control of the NSA framework, and
// "v2.0.301", which holds three of them, so that a scan can tell which release
// its policies came from. It counts the requests made for each file.
type regolibraryReleases struct {
	*httptest.Server
	mu       sync.Mutex
	requests map[string]int
}

const releaseDownloadPath = "/kubescape/regolibrary/releases/download/"

func newRegolibraryReleases(t *testing.T) *regolibraryReleases {
	t.Helper()
	read := func(parts ...string) []byte {
		data, err := os.ReadFile(filepath.Join(parts...))
		require.NoError(t, err)
		return data
	}
	var nsa map[string]any
	require.NoError(t, json.Unmarshal(read("..", "cautils", "getter", "testdata", "NSA.json"), &nsa))
	controls := nsa["controls"].([]any)
	require.Greater(t, len(controls), 3)

	frameworkOf := func(controls []any) []byte {
		framework := map[string]any{}
		for key, value := range nsa {
			framework[key] = value
		}
		framework["controls"] = controls
		delete(framework, "controlsIDs")
		data, err := json.Marshal([]any{framework})
		require.NoError(t, err)
		return data
	}
	controlsOf := func(controls []any) []byte {
		data, err := json.Marshal(controls)
		require.NoError(t, err)
		return data
	}
	configInputs, err := json.Marshal(map[string]any{"settings": map[string]any{"postureControlInputs": json.RawMessage(read("..", "cautils", "getter", "testdata", "controls-inputs.json"))}})
	require.NoError(t, err)

	releases := map[string][]any{"v2": controls, "v2.0.301": controls[:3]}
	r := &regolibraryReleases{requests: map[string]int{}}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		tag, file, _ := strings.Cut(strings.TrimPrefix(req.URL.Path, "/"), "/")
		r.mu.Lock()
		r.requests[tag+"/"+file]++
		r.mu.Unlock()

		release, ok := releases[tag]
		if !ok {
			http.NotFound(w, req)
			return
		}
		switch file {
		case "frameworks":
			_, _ = w.Write(frameworkOf(release))
		case "controls":
			_, _ = w.Write(controlsOf(release))
		case "default_config_inputs":
			_, _ = w.Write(configInputs)
		case "FWName_CID_CName":
			fmt.Fprint(w, "frameworkName,ControlID,ControlName\n")
		case "ControlID_RuleName":
			fmt.Fprint(w, "ControlID,RuleName\n")
		case "rules", "attack_tracks", "exceptions", "security_frameworks":
			fmt.Fprint(w, "[]")
		default: // checksums.txt, checksums.sigstore.json: an unsigned release
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(r.Close)

	// The store's HTTP client has no transport of its own, so it uses the
	// default one, which is pointed at this server for the test. Nothing else is
	// let out: a request to anywhere but here fails the scan that made it.
	target, err := url.Parse(r.URL)
	require.NoError(t, err)
	original := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "github.com" && strings.HasPrefix(req.URL.Path, releaseDownloadPath) {
			redirected := req.Clone(req.Context())
			redirected.URL.Scheme, redirected.URL.Host = "http", target.Host
			redirected.URL.Path = "/" + strings.TrimPrefix(req.URL.Path, releaseDownloadPath)
			redirected.Host = target.Host
			return original.RoundTrip(redirected)
		}
		if host, _, err := net.SplitHostPort(req.URL.Host); err == nil && host == "127.0.0.1" {
			return original.RoundTrip(req)
		}
		return nil, errors.New("the test lets nothing out but the regolibrary release: " + req.URL.String())
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	return r
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// downloads is how many times the release's files were asked for: the checksums,
// which every download asks for first, are asked for once per download.
func (r *regolibraryReleases) downloads(tag string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests[tag+"/checksums.txt"]
}

func (r *regolibraryReleases) totalRequests() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for _, count := range r.requests {
		total += count
	}
	return total
}

// keepScansOffTheCluster stops a scan from reading a kubeconfig, so that these
// tests behave the same on a machine that has one.
func keepScansOffTheCluster(t *testing.T) {
	t.Helper()
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "no-kubeconfig"))
	previousAPI := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi { return nil }
	previousConnected := k8sinterface.IsConnectedToCluster()
	k8sinterface.SetConnectedToCluster(false)
	t.Cleanup(func() {
		kubernetesAPIFunc = previousAPI
		k8sinterface.SetConnectedToCluster(previousConnected)
	})
}

type nsaScan struct {
	// controls is the number of controls the scan evaluated.
	controls int
	// report is the JSON report with what differs from one run to the next left
	// out.
	report map[string]any
}

// scanNSA scans the manifests in dir for the NSA framework with the policies of
// the release the scan names, the way `kubescape scan framework nsa` does.
func scanNSA(t *testing.T, dir, controlsVersion string, store *getter.DownloadReleasedPolicy) nsaScan {
	t.Helper()
	scanInfo := &cautils.ScanInfo{
		InputPatterns:       []string{dir},
		ControlsVersion:     controlsVersion,
		ReleasedPolicyStore: store,
		Local:               true,
		FrameworkScan:       true,
	}
	scanInfo.SetScanType(cautils.ScanTypeFramework)
	scanInfo.Submit.SetBool(false)

	results, err := NewKubescape(context.Background()).Scan(scanInfo, cautils.BuildPolicyIdentifiers([]string{"nsa"}, apisv1.KindFramework))
	require.NoError(t, err)
	require.NotNil(t, results)
	assert.Same(t, store, scanInfo.ReleasedPolicyStore, "a scan does not replace the store it was given")

	reportJSON, err := results.ToJson()
	require.NoError(t, err)
	var report map[string]any
	require.NoError(t, json.Unmarshal(reportJSON, &report))
	for _, volatile := range []string{"generationTime", "reportGUID", "jobID"} {
		delete(report, volatile)
	}
	return nsaScan{controls: len(results.GetData().Report.SummaryDetails.Controls), report: report}
}

func writePodManifest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pod.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n  namespace: default\nspec:\n  containers:\n  - name: c\n    image: nginx\n"), 0o600))
	return dir
}

// A store the caller keeps is the one a scan reads its policies from: the first
// scan downloads the release into it, and no later scan of that release asks for
// it again. The proof is the requests that reach the release, counted, not how
// long a scan took.
func TestScanContextReusesTheCallersReleasedPolicyStore(t *testing.T) {
	keepScansOffTheCluster(t)
	releases := newRegolibraryReleases(t)
	dir := writePodManifest(t)
	store := getter.NewDownloadReleasedPolicy()

	first := scanNSA(t, dir, "", store)
	require.Equal(t, 1, releases.downloads("v2"), "the first scan downloaded the latest release into the store")
	requestsAfterFirst := releases.totalRequests()
	require.Greater(t, first.controls, 3)

	second := scanNSA(t, dir, "", store)
	third := scanNSA(t, dir, "", store)

	assert.Equal(t, 1, releases.downloads("v2"), "the later scans did not download the release again")
	assert.Equal(t, requestsAfterFirst, releases.totalRequests(), "they asked the release for nothing at all")
	assert.Equal(t, first.report, second.report, "a scan served from the store reports what the scan that filled it did")
	assert.Equal(t, first.report, third.report)
}

// Without a store of its own a scan downloads the release, as it always did, and
// reports what a scan served from a kept store reports for the same manifests.
func TestScanContextWithoutAKeptStoreDownloadsEachTimeAndReportsTheSame(t *testing.T) {
	keepScansOffTheCluster(t)
	releases := newRegolibraryReleases(t)
	dir := writePodManifest(t)
	store := getter.NewDownloadReleasedPolicy()

	kept := scanNSA(t, dir, "", store)
	plainFirst := scanNSA(t, dir, "", nil)
	plainSecond := scanNSA(t, dir, "", nil)

	assert.Equal(t, 3, releases.downloads("v2"), "one download for the kept store, and one for each scan that had none")
	assert.Equal(t, kept.report, plainFirst.report, "the report does not depend on where the policies were kept")
	assert.Equal(t, kept.report, plainSecond.report)
}

// A store holds one release. A scan that asks for another does not take its
// policies from the store, and does not change what the store holds.
func TestScanContextDoesNotServeAKeptStoreToAScanOfAnotherRelease(t *testing.T) {
	keepScansOffTheCluster(t)
	releases := newRegolibraryReleases(t)
	dir := writePodManifest(t)
	store := getter.NewDownloadReleasedPolicy()

	latest := scanNSA(t, dir, "", store)
	require.Equal(t, 1, releases.downloads("v2"))
	require.Zero(t, releases.downloads("v2.0.301"))

	pinned := scanNSA(t, dir, "v2.0.301", store)
	assert.Equal(t, 1, releases.downloads("v2.0.301"), "the pinned release was downloaded for the scan that pinned it")
	assert.Equal(t, 3, pinned.controls, "and the scan was judged by it, not by the latest release in the store")
	assert.Greater(t, latest.controls, pinned.controls)

	requestsBefore := releases.totalRequests()
	again := scanNSA(t, dir, "", store)
	assert.Equal(t, requestsBefore, releases.totalRequests(), "the store still holds the latest release, whole, after the pinned scan")
	assert.Equal(t, latest.report, again.report)
	assert.Equal(t, 1, releases.downloads("v2"))
}

// Scans that run at the same time, each with a ScanInfo of its own and the one
// store between them, download the release once. Run with -race this checks that
// sharing the store is free of data races through the whole of ScanContext.
func TestScanContextConcurrentScansShareOneDownload(t *testing.T) {
	keepScansOffTheCluster(t)
	releases := newRegolibraryReleases(t)
	dir := writePodManifest(t)
	store := getter.NewDownloadReleasedPolicy()

	const scans = 5
	var wg sync.WaitGroup
	results := make([]nsaScan, scans)
	for i := 0; i < scans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// scanNSA fails the test from a goroutine only through t.Errorf-style
			// helpers; a scan that fails here leaves its result empty and is
			// caught below.
			results[i] = scanNSAQuietly(dir, store)
		}()
	}
	wg.Wait()

	for i := range results {
		require.NotNil(t, results[i].report, "scan %d failed", i)
		assert.Equal(t, results[0].report, results[i].report, "scan %d", i)
	}
	assert.Equal(t, 1, releases.downloads("v2"), "five scans started together downloaded the release once")
}

// scanNSAQuietly is scanNSA for use from a goroutine: it reports a failed scan as
// an empty result and not by failing the test.
func scanNSAQuietly(dir string, store *getter.DownloadReleasedPolicy) nsaScan {
	scanInfo := &cautils.ScanInfo{InputPatterns: []string{dir}, ReleasedPolicyStore: store, Local: true, FrameworkScan: true}
	scanInfo.SetScanType(cautils.ScanTypeFramework)
	scanInfo.Submit.SetBool(false)
	results, err := NewKubescape(context.Background()).Scan(scanInfo, cautils.BuildPolicyIdentifiers([]string{"nsa"}, apisv1.KindFramework))
	if err != nil || results == nil {
		return nsaScan{}
	}
	reportJSON, err := results.ToJson()
	if err != nil {
		return nsaScan{}
	}
	var report map[string]any
	if json.Unmarshal(reportJSON, &report) != nil {
		return nsaScan{}
	}
	for _, volatile := range []string{"generationTime", "reportGUID", "jobID"} {
		delete(report, volatile)
	}
	return nsaScan{controls: len(results.GetData().Report.SummaryDetails.Controls), report: report}
}

// A scan that is cancelled while it waits for the release stops with the
// context's error, and does not go on with the policies it has cached.
func TestScanContextCancelledWhileTheReleaseDownloadsStops(t *testing.T) {
	keepScansOffTheCluster(t)
	newRegolibraryReleases(t) // installs the transport; the scan below never gets to use it
	dir := writePodManifest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{dir}, ReleasedPolicyStore: getter.NewDownloadReleasedPolicy(), Local: true, FrameworkScan: true}
	scanInfo.SetScanType(cautils.ScanTypeFramework)
	scanInfo.Submit.SetBool(false)
	results, err := NewKubescape(ctx).ScanContext(ctx, scanInfo, cautils.BuildPolicyIdentifiers([]string{"nsa"}, apisv1.KindFramework))

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, results)
}

// The store a scan reads from is chosen by release, and only by release.
func TestReleasedPolicyStoreFor(t *testing.T) {
	latest := getter.NewDownloadReleasedPolicyWithVersion("")
	pinned := getter.NewDownloadReleasedPolicyWithVersion("v2.0.301")

	t.Run("without a kept store the scan makes its own", func(t *testing.T) {
		scan := &cautils.ScanInfo{}
		first, second := releasedPolicyStoreFor(scan), releasedPolicyStoreFor(scan)
		require.NotNil(t, first)
		assert.NotSame(t, first, second, "nothing is kept between scans unless the caller keeps it")
		assert.False(t, first.IsVersionPinned())
	})
	t.Run("a kept store is used again by every scan of its release", func(t *testing.T) {
		scan := &cautils.ScanInfo{ReleasedPolicyStore: latest}
		assert.Same(t, latest, releasedPolicyStoreFor(scan))
		assert.Same(t, latest, releasedPolicyStoreFor(scan))
	})
	t.Run("a kept store of a pinned release serves a scan that pins it", func(t *testing.T) {
		scan := &cautils.ScanInfo{ReleasedPolicyStore: pinned, ControlsVersion: "v2.0.301"}
		assert.Same(t, pinned, releasedPolicyStoreFor(scan))
	})
	t.Run("a kept store of another release is not used", func(t *testing.T) {
		store := releasedPolicyStoreFor(&cautils.ScanInfo{ReleasedPolicyStore: latest, ControlsVersion: "v2.0.301"})
		assert.NotSame(t, latest, store)
		assert.True(t, store.IsVersionPinned(), "the scan gets the release it asked for")

		store = releasedPolicyStoreFor(&cautils.ScanInfo{ReleasedPolicyStore: pinned})
		assert.NotSame(t, pinned, store)
		assert.False(t, store.IsVersionPinned())

		assert.NotSame(t, pinned, releasedPolicyStoreFor(&cautils.ScanInfo{ReleasedPolicyStore: pinned, ControlsVersion: "v2.0.302"}))
	})
}
