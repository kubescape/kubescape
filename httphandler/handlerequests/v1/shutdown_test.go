package v1

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/httphandler/config"
	"github.com/kubescape/kubescape/v4/httphandler/storage"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// Run inside synctest so the negative join assertions wait until all runnable
// goroutines have settled, rather than depending on scheduler timing.
func TestShutdown_CancellationMustJoinAsyncScan(t *testing.T) {
	withTempOutputDirs(t)
	synctest.Test(t, func(t *testing.T) {
		started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		original := scanImpl
		defer func() { scanImpl = original }()
		scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
			close(started)
			<-ctx.Done()
			close(cancelled)
			<-release
			return nil, ctx.Err()
		}
		h := NewHTTPHandler(false)
		response := performAsyncScanRequest(t, h, `{}`)
		require.Equal(t, http.StatusOK, response.Code)
		id := decodeScanResponse(t, response).ID
		<-started
		done := make(chan error, 1)
		go func() { done <- h.Shutdown(context.Background(), time.Second) }()
		time.Sleep(time.Second) // virtual drain deadline
		<-cancelled
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("shutdown returned before executeScan: %v", err)
		default:
		}
		require.True(t, h.state.isBusy(id))
		close(release)
		require.NoError(t, <-done)
		require.Zero(t, h.state.len())
		<-h.workerDone
	})
}

func TestShutdown_HardDeadlineReportsUnjoinedWorker(t *testing.T) {
	withTempOutputDirs(t)
	synctest.Test(t, func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		original := scanImpl
		defer func() { scanImpl = original }()
		scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
			close(started)
			<-release
			return nil, ctx.Err()
		}
		h := NewHTTPHandler(false)
		performAsyncScanRequest(t, h, `{}`)
		<-started
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		require.ErrorIs(t, h.Shutdown(ctx, time.Second), context.DeadlineExceeded)
		require.Equal(t, 1, h.state.len(), "timing out must not claim work completed")
		select {
		case <-h.workerDone:
			t.Fatal("worker exited before the scan returned")
		default:
		}
		close(release)
		require.NoError(t, h.Shutdown(context.Background(), 0))
		require.Zero(t, h.state.len())
	})
}

func TestShutdown_DrainsAcceptedScansAndRejectsAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		var executed []string
		original := scanImpl
		defer func() { scanImpl = original }()
		scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, id string, _ bool) (*reporthandlingv2.PostureReport, error) {
			if len(executed) == 0 {
				close(started)
				<-release // includes time spent persisting inside scanImpl
			}
			assert.NoError(t, ctx.Err())
			executed = append(executed, id)
			return nil, nil
		}
		h := NewHTTPHandler(false)
		first := decodeScanResponse(t, performAsyncScanRequest(t, h, `{}`)).ID
		<-started
		second := decodeScanResponse(t, performAsyncScanRequest(t, h, `{}`)).ID
		h.BeginShutdown()
		require.Equal(t, http.StatusServiceUnavailable, performAsyncScanRequest(t, h, `{}`).Code)
		metrics := httptest.NewRecorder()
		h.Metrics(metrics, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))
		require.Equal(t, http.StatusServiceUnavailable, metrics.Code)
		done := make(chan error, 2)
		for range 2 {
			go func() { done <- h.Shutdown(context.Background(), time.Minute) }()
		}
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("shutdown did not wait for persistence")
		default:
		}
		close(release)
		require.NoError(t, <-done)
		require.NoError(t, <-done)
		require.Equal(t, []string{first, second}, executed)
		require.Zero(t, h.state.len())
		require.Zero(t, len(h.scanRequestChan))
	})
}

func TestShutdown_CancelsQueueAndReleasesWaiters(t *testing.T) {
	withTempOutputDirs(t)
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		calls := 0
		original := scanImpl
		defer func() { scanImpl = original }()
		scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
			calls++
			if calls == 1 {
				close(started)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		h := NewHTTPHandler(false)
		performAsyncScanRequest(t, h, `{}`)
		<-started
		responses := make(chan *httptest.ResponseRecorder, 2)
		go func() {
			w := httptest.NewRecorder()
			h.Scan(w, httptest.NewRequest(http.MethodPost, "/v1/scan?wait=true", strings.NewReader(`{}`)))
			responses <- w
		}()
		go func() {
			w := httptest.NewRecorder()
			h.Metrics(w, httptest.NewRequest(http.MethodGet, "/v1/metrics", nil))
			responses <- w
		}()
		synctest.Wait()
		require.Equal(t, 3, h.state.len())
		require.NoError(t, h.Shutdown(context.Background(), 0))
		for range 2 {
			w := <-responses
			require.Equal(t, http.StatusInternalServerError, w.Code)
			require.Equal(t, utilsapisv1.ErrorScanResponseType, decodeScanResponse(t, w).Type)
		}
		require.Equal(t, 1, calls)
		require.Zero(t, h.state.len())
	})
}

func TestShutdown_AdmissionRace(t *testing.T) {
	// Exercise both producer kinds without starting a worker: every accepted
	// request must be present exactly once in the closed queue.
	h := &HTTPHandler{state: newServerState(), scanRequestChan: make(chan *scanRequestParams, 100)}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 100 {
		wg.Go(func() {
			<-start
			ctx, cancel := context.WithCancel(context.Background())
			req := &scanRequestParams{scanID: fmt.Sprint(i), ctx: ctx, isUserScan: i%2 == 0}
			err := h.enqueueScan(req, cancel)
			if err != nil {
				assert.ErrorIs(t, err, errShuttingDown)
				assert.ErrorIs(t, ctx.Err(), context.Canceled)
			}
		})
	}
	wg.Go(func() { <-start; h.BeginShutdown() })
	close(start)
	wg.Wait()
	accepted := h.state.len()
	count := 0
	for req := range h.scanRequestChan {
		count++
		h.state.releaseCancel(req.scanID)
		h.state.setNotBusy(req.scanID)
	}
	require.Equal(t, accepted, count)
	require.Zero(t, h.state.len())
}

func TestShutdown_DisconnectedWaiterDoesNotReleaseScan(t *testing.T) {
	for _, mode := range []string{"scan", "metrics", "keep"} {
		t.Run(mode, func(t *testing.T) {
			withTempOutputDirs(t)
			metrics := mode == "metrics"
			synctest.Test(t, func(t *testing.T) {
				started, release := make(chan struct{}), make(chan struct{})
				var artifacts []string
				original := scanImpl
				defer func() { scanImpl = original }()
				scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, id string, _ bool) (*reporthandlingv2.PostureReport, error) {
					artifacts = []string{filepath.Join(OutputDir, id), filepath.Join(OutputDir, id+".json")}
					for _, path := range artifacts {
						assert.NoError(t, os.WriteFile(path, []byte("partial"), 0600))
					}
					close(started)
					<-release
					assert.NoError(t, ctx.Err())
					for _, path := range artifacts {
						assert.NoError(t, os.WriteFile(path, []byte("complete"), 0600))
					}
					return nil, nil
				}
				h := NewHTTPHandler(false)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan struct{})
				go func() {
					defer close(done)
					w := httptest.NewRecorder()
					if metrics {
						h.Metrics(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/metrics", nil))
					} else {
						h.Scan(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/scan?wait=true&keep="+fmt.Sprint(mode == "keep"), strings.NewReader(`{}`)))
					}
				}()
				<-started
				cancel()
				<-done
				require.Equal(t, 1, h.state.len())
				synctest.Wait()
				for _, path := range artifacts {
					require.FileExists(t, path, "cleanup must wait for the writer")
				}
				close(release)
				require.NoError(t, h.Shutdown(context.Background(), time.Minute))
				synctest.Wait()
				for _, path := range artifacts {
					if mode == "keep" {
						require.FileExists(t, path)
					} else {
						require.NoFileExists(t, path)
					}
				}
			})
		})
	}
}

func TestShutdown_JoinsActualStoragePersistence(t *testing.T) {
	withTempOutputDirs(t)
	originalScan, originalRun := scanImpl, runKubescapeScan
	originalStorage, originalAccount := storage.GetStorage(), config.GetAccount()
	t.Cleanup(func() {
		scanImpl, runKubescapeScan = originalScan, originalRun
		storage.SetStorage(originalStorage)
		config.SetAccount(originalAccount)
	})
	synctest.Test(t, func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		//nolint:staticcheck // The pinned storage client lacks the summary apply schema required by NewClientset.
		client := fake.NewSimpleClientset()
		client.PrependReactor("create", "workloadconfigurationscansummaries", func(k8stesting.Action) (bool, runtime.Object, error) {
			close(started)
			<-release
			return false, nil, nil // continue through the real fake-client store
		})
		store, err := storage.NewAPIServerStorage("test-cluster", "default", client.SpdxV1beta1(), false)
		require.NoError(t, err)
		storage.SetStorage(store)
		config.SetAccount("")
		scanImpl = scan
		runKubescapeScan = func(_ context.Context, info *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
			results := newFormatLifecycleResultsHandler(info.Output, "", []byte(`{}`))
			data := cautils.NewOPASessionObjMock()
			data.Report.ClusterName = "test-cluster"
			obj := workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1", "kind": "Pod",
				"metadata": map[string]any{"name": "shutdown-test", "namespace": "default"},
			})
			id := obj.GetID()
			data.AllResources[id] = obj
			data.ResourcesResult[id] = resourcesresults.Result{ResourceID: id}
			results.SetData(data)
			return results, nil
		}
		h := NewHTTPHandler(false)
		performAsyncScanRequest(t, h, `{}`)
		<-started
		done := make(chan error, 1)
		go func() { done <- h.Shutdown(context.Background(), time.Minute) }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("shutdown returned while storage Create was blocked: %v", err)
		default:
		}
		close(release)
		require.NoError(t, <-done)
		stored, err := client.SpdxV1beta1().WorkloadConfigurationScanSummaries("default").List(context.Background(), metav1.ListOptions{})
		require.NoError(t, err)
		require.Len(t, stored.Items, 1)
		require.Zero(t, h.state.len())
	})
}
