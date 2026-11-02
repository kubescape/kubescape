package imagescan

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

type gcpLifecycleAPI func(context.Context, *grafeaspb.ListOccurrencesRequest) GrafeasIterator

func (f gcpLifecycleAPI) ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, _ ...interface{}) GrafeasIterator {
	return f(ctx, req)
}

func TestGCPActiveBatchPreventsClientReplacement(t *testing.T) {
	for _, operation := range []string{"status", "findings"} {
		for _, transition := range []string{"login", "failed login", "destroy"} {
			t.Run(operation+"/"+transition, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				entered, resume := make(chan struct{}), make(chan struct{})
				var unblock sync.Once
				defer unblock.Do(func() { close(resume) })
				owner := newFakeContainerAnalysisClient(t)
				a := NewGCPAdaptor()
				a.owningClient, a.projectID = owner, "original"
				oldCalls := 0
				a.client = gcpLifecycleAPI(func(ctx context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
					oldCalls++
					if req.Parent != "projects/original" {
						return &mockGrafeasIterator{err: fmt.Errorf("project changed: %s", req.Parent)}
					}
					if oldCalls == 1 {
						close(entered)
						select {
						case <-resume:
						case <-ctx.Done():
							return &mockGrafeasIterator{err: ctx.Err()}
						}
					}
					if strings.Contains(req.Filter, `kind="DISCOVERY"`) {
						return &mockGrafeasIterator{occurrences: []*grafeaspb.Occurrence{
							discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{}),
						}}
					}
					return &mockGrafeasIterator{occurrences: []*grafeaspb.Occurrence{{
						NoteName: "projects/advisories/notes/CVE-original",
						Details: &grafeaspb.Occurrence_Vulnerability{Vulnerability: &grafeaspb.VulnerabilityOccurrence{
							EffectiveSeverity: grafeaspb.Severity_HIGH,
						}},
					}}}
				})
				newOwner := newFakeContainerAnalysisClient(t)
				a.clientFactory = func(context.Context) (*containeranalysis.Client, error) { return newOwner, nil }
				var newCalls atomic.Int32
				a.apiFactory = func(*containeranalysis.Client) GCPAPI {
					return gcpLifecycleAPI(func(_ context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
						newCalls.Add(1)
						if req.Parent != "projects/replacement" {
							return &mockGrafeasIterator{err: fmt.Errorf("wrong replacement project: %s", req.Parent)}
						}
						return &mockGrafeasIterator{}
					})
				}
				defer func() { _ = a.Destroy() }()
				images := []ContainerImageIdentifier{{Registry: "us-docker.pkg.dev", Repository: "original/repo/app", Hash: "sha256:abc"}}
				if operation == "status" {
					images = append(images, images[0])
				}
				completed := make(chan error, 1)
				go func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							completed <- fmt.Errorf("in-flight scan panicked: %v", recovered)
						}
					}()
					if operation == "status" {
						statuses, err := a.GetImagesScanStatus(ctx, images)
						if err == nil && (len(statuses) != 2 || !statuses[0].IsScanAvailable || !statuses[1].IsScanAvailable) {
							err = fmt.Errorf("batch lost an available scan")
						}
						completed <- err
						return
					}
					reports, err := a.GetImagesVulnerabilities(ctx, images)
					if err == nil && (len(reports) != 1 || reports[0].Status != ScanStatusScanned || len(reports[0].Vulnerabilities) != 1 || reports[0].Vulnerabilities[0].ID != "CVE-original") {
						err = fmt.Errorf("discovery and findings did not retain one session")
					}
					completed <- err
				}()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("original scan never started")
				}
				transitionStarted, transitioned := make(chan struct{}), make(chan error, 1)
				go func() {
					close(transitionStarted)
					if transition == "destroy" {
						transitioned <- a.Destroy()
						return
					}
					credentials := RegistryCredentials{}
					if transition == "failed login" {
						credentials.Token = "unsupported"
					}
					transitioned <- a.Login(ctx, "us-docker.pkg.dev/replacement/repo", credentials)
				}()
				<-transitionStarted
				var transitionErr error
				early := false
				select {
				case transitionErr = <-transitioned:
					early = true
					t.Error("client lifecycle changed while a scan still owned its iterator")
				case <-time.After(30 * time.Millisecond):
				}
				unblock.Do(func() { close(resume) })
				select {
				case err := <-completed:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("scan did not finish")
				}
				if !early {
					select {
					case transitionErr = <-transitioned:
					case <-ctx.Done():
						t.Fatal("lifecycle operation did not resume")
					}
				}
				if transition == "failed login" {
					require.ErrorContains(t, transitionErr, "explicit credentials")
				} else {
					require.NoError(t, transitionErr)
				}
				require.Equal(t, 2, oldCalls)
				require.Error(t, owner.Close(), "retired gRPC client must be closed exactly once by the adaptor")
				_, err := a.GetImagesScanStatus(ctx, images[:1])
				if transition == "login" {
					require.NoError(t, err)
					require.EqualValues(t, 2, newCalls.Load(), "only the login probe and later batch use the replacement")
				} else {
					require.ErrorContains(t, err, "not initialized")
					require.Zero(t, newCalls.Load())
				}
			})
		}
	}
}

func TestGCPFailedProbeCannotServeConcurrentScan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := NewGCPAdaptor()
	owner := newFakeContainerAnalysisClient(t)
	a.clientFactory = func(context.Context) (*containeranalysis.Client, error) { return owner, nil }
	entered, resume := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(resume) })
	var requests atomic.Int32
	a.apiFactory = func(*containeranalysis.Client) GCPAPI {
		return gcpLifecycleAPI(func(ctx context.Context, _ *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
			if requests.Add(1) == 1 {
				close(entered)
				select {
				case <-resume:
				case <-ctx.Done():
				}
				return &mockGrafeasIterator{err: fmt.Errorf("fixture access denied")}
			}
			return &mockGrafeasIterator{}
		})
	}
	loginDone := make(chan error, 1)
	go func() { loginDone <- a.Login(ctx, "us-docker.pkg.dev/project/repo", RegistryCredentials{}) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("probe never started")
	}
	scanDone := make(chan error, 1)
	go func() {
		_, err := a.GetImagesScanStatus(ctx, []ContainerImageIdentifier{{Hash: "sha256:abc"}})
		scanDone <- err
	}()
	unblock.Do(func() { close(resume) })
	require.ErrorContains(t, <-loginDone, "fixture access denied")
	require.ErrorContains(t, <-scanDone, "not initialized")
	require.EqualValues(t, 1, requests.Load(), "an unverified candidate must never serve scans")
	require.Error(t, owner.Close(), "failed probe closes its candidate")
}

func TestGCPIndependentReadersCanRunTogether(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, resume := make(chan struct{}, 2), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(resume) })
	a := NewGCPAdaptor()
	a.client = gcpLifecycleAPI(func(ctx context.Context, _ *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		entered <- struct{}{}
		select {
		case <-resume:
		case <-ctx.Done():
		}
		return &mockGrafeasIterator{err: iterator.Done}
	})
	completed := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := a.GetImagesScanStatus(ctx, []ContainerImageIdentifier{{Hash: "sha256:abc"}})
			completed <- err
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("independent scan batches were serialized")
		}
	}
	unblock.Do(func() { close(resume) })
	for i := 0; i < 2; i++ {
		require.NoError(t, <-completed)
	}
}

func TestGCPDestroyInvalidatesNonOwningSession(t *testing.T) {
	a := NewGCPAdaptor()
	a.projectID, a.client = "retired", &mockGCPClient{}
	require.NoError(t, a.Destroy())
	require.NoError(t, a.Destroy(), "repeated cleanup remains safe")
	ctx := context.Background()
	images := []ContainerImageIdentifier{{Hash: "sha256:abc"}}
	_, err := a.GetImagesScanStatus(ctx, images)
	require.ErrorContains(t, err, "not initialized")
	_, err = a.GetImagesVulnerabilities(ctx, images)
	require.ErrorContains(t, err, "not initialized")
	_, err = a.GetImagesInformation(ctx, images)
	require.ErrorContains(t, err, "not initialized")
	require.Empty(t, a.projectID)
}

func TestGCPCancelledReaderReleasesClientForDestroy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	a := NewGCPAdaptor()
	a.owningClient = newFakeContainerAnalysisClient(t)
	a.client = gcpLifecycleAPI(func(ctx context.Context, _ *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
		close(entered)
		<-ctx.Done()
		return &mockGrafeasIterator{err: ctx.Err()}
	})
	scanDone := make(chan error, 1)
	go func() {
		_, err := a.GetImagesScanStatus(ctx, []ContainerImageIdentifier{{Hash: "sha256:abc"}})
		scanDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not start")
	}
	cancel()
	require.ErrorIs(t, <-scanDone, context.Canceled)
	destroyDone := make(chan error, 1)
	go func() { destroyDone <- a.Destroy() }()
	select {
	case err := <-destroyDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled scan retained the client lock")
	}
}
