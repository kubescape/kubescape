package imagescan

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/stretchr/testify/require"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

func TestGCPLifecycleWaitsForActiveScan(t *testing.T) {
	for _, operation := range []string{"status batch", "vulnerabilities"} {
		for _, lifecycle := range []string{"rejected login", "successful login", "destroy"} {
			t.Run(operation+"/"+lifecycle, func(t *testing.T) {
				// Provider queries use fakes; the owning transport is present only
				// so the test also exercises connection cleanup.
				owner := newFakeContainerAnalysisClient(t)
				t.Cleanup(func() { _ = owner.Close() })
				func(t *testing.T) {
					entered := make(chan struct{})
					resume := make(chan struct{})
					queries := 0
					oldAPI := &partialGCPAPI{call: func(_ context.Context, req *grafeaspb.ListOccurrencesRequest) GrafeasIterator {
						queries++
						if queries == 1 {
							close(entered)
							<-resume
						}
						if req.Parent != "projects/old-project" {
							t.Errorf("active scan switched project: %s", req.Parent)
						}
						if strings.Contains(req.Filter, `kind="DISCOVERY"`) {
							return &mockGrafeasIterator{}
						}
						return &mockGrafeasIterator{occurrences: []*grafeaspb.Occurrence{partialGCPVulnerability("CVE-old")}}
					}}
					newAPI := &partialGCPAPI{}
					adaptor := &GCPAdaptor{client: oldAPI, owningClient: owner, projectID: "old-project"}
					adaptor.clientFactory = func(context.Context) (*containeranalysis.Client, error) { return nil, nil }
					adaptor.apiFactory = func(*containeranalysis.Client) GCPAPI { return newAPI }
					images := []ContainerImageIdentifier{partialGCPImage()}
					if operation == "status batch" {
						images = append(images, images[0])
					}
					scanDone := make(chan error, 1)
					go func() {
						defer func() {
							if value := recover(); value != nil {
								scanDone <- fmt.Errorf("active scan panicked: %v", value)
							}
						}()
						if operation == "status batch" {
							statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
							if err == nil && len(statuses) != 2 {
								err = fmt.Errorf("lost an image in the active batch")
							}
							scanDone <- err
						} else {
							reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
							if err == nil && (len(reports) != 1 || len(reports[0].Vulnerabilities) != 1 || reports[0].Vulnerabilities[0].ID != "CVE-old") {
								err = fmt.Errorf("active report did not retain the original session's findings")
							}
							scanDone <- err
						}
					}()
					<-entered
					lifecycleDone := make(chan error, 1)
					go func() {
						switch lifecycle {
						case "rejected login":
							lifecycleDone <- adaptor.Login(context.Background(), "us-docker.pkg.dev/new-project/repo", RegistryCredentials{Token: "unsupported"})
						case "successful login":
							lifecycleDone <- adaptor.Login(context.Background(), "us-docker.pkg.dev/new-project/repo", RegistryCredentials{})
						case "destroy":
							lifecycleDone <- adaptor.Destroy()
						}
					}()
					// Keep the provider blocked while the lifecycle goroutine attempts
					// replacement. Only this negative assertion uses a bounded wait.
					var earlyError error
					early := false
					select {
					case earlyError = <-lifecycleDone:
						early = true
						t.Error("lifecycle operation finished while its client was still in use")
					case <-time.After(30 * time.Millisecond):
					}
					close(resume)
					select {
					case err := <-scanDone:
						require.NoError(t, err)
					case <-time.After(5 * time.Second):
						t.Fatal("active scan did not finish after release")
					}
					lifecycleErr := earlyError
					if !early {
						select {
						case lifecycleErr = <-lifecycleDone:
						case <-time.After(5 * time.Second):
							t.Fatal("lifecycle operation did not finish after scan")
						}
					}
					if lifecycle == "rejected login" {
						require.Error(t, lifecycleErr)
					} else {
						require.NoError(t, lifecycleErr)
					}
					require.Equal(t, 2, queries)
					_, err := adaptor.GetImagesScanStatus(context.Background(), images[:1])
					if lifecycle == "successful login" {
						require.NoError(t, err)
						require.Equal(t, "projects/new-project", newAPI.requests[len(newAPI.requests)-1].Parent)
					} else {
						require.ErrorContains(t, err, "client not initialized")
					}
				}(t)
			})
		}
	}
}

func TestGCPConcurrentLoginAndReadMethods(t *testing.T) {
	adaptor := NewGCPAdaptor()
	adaptor.clientFactory = func(context.Context) (*containeranalysis.Client, error) { return nil, nil }
	adaptor.apiFactory = func(*containeranalysis.Client) GCPAPI {
		return &mockGCPClient{}
	}
	ctx := context.Background()
	const registry = "us-docker.pkg.dev/project/repo"
	require.NoError(t, adaptor.Login(ctx, registry, RegistryCredentials{}))
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Go(func() {
			for i := 0; i < 30; i++ {
				// Empty batches exercise the public initialization paths without
				// introducing a mutable fake iterator shared by reader goroutines.
				var err error
				switch worker {
				case 0:
					err = adaptor.Login(ctx, registry, RegistryCredentials{})
				case 1:
					_, err = adaptor.GetImagesScanStatus(ctx, nil)
				case 2:
					_, err = adaptor.GetImagesVulnerabilities(ctx, nil)
				case 3:
					_, err = adaptor.GetImagesInformation(ctx, nil)
				}
				if err != nil {
					t.Errorf("unexpected concurrent operation error: %v", err)
				}
			}
		})
	}
	workers.Wait()
}

type parallelGCPAPI struct {
	entered chan<- struct{}
	resume  <-chan struct{}
}

func (api parallelGCPAPI) ListOccurrences(context.Context, *grafeaspb.ListOccurrencesRequest, ...interface{}) GrafeasIterator {
	api.entered <- struct{}{}
	<-api.resume
	return &mockGrafeasIterator{}
}

func TestGCPSessionAllowsConcurrentScans(t *testing.T) {
	entered, resume := make(chan struct{}, 2), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	defer unblock()
	adaptor := &GCPAdaptor{client: parallelGCPAPI{entered: entered, resume: resume}, projectID: "project"}
	done := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{partialGCPImage()})
			done <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("independent scans were serialized instead of sharing the session")
		}
	}
	unblock()
	for range 2 {
		require.NoError(t, <-done)
	}
}
