package imagescan

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/stretchr/testify/require"
)

func azureSessionResponse(id string) armresourcegraph.ClientResourcesResponse {
	return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
		TotalRecords: to.Ptr[int64](1),
		Data: []interface{}{map[string]interface{}{
			"id": id, "severity": "High", "timeGenerated": "2026-10-01T12:00:00Z",
		}},
	}}
}

func TestAzureBatchRetainsSessionDuringRelogin(t *testing.T) {
	for _, operation := range []string{"status batch", "finding pages", "empty findings fallback"} {
		for _, replacement := range []string{"same registry", "different registry", "rejected login"} {
			t.Run(operation+"/"+replacement, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				entered, resume := make(chan struct{}), make(chan struct{})
				var unblock sync.Once
				defer unblock.Do(func() { close(resume) })
				oldCalls := 0
				oldClient := &mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
					oldCalls++
					if !strings.Contains(*req.Query, `registryName =~ "old"`) {
						return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("query lost its registry: %s", *req.Query)
					}
					if oldCalls == 1 {
						close(entered)
						select {
						case <-resume:
						case <-ctx.Done():
							return armresourcegraph.ClientResourcesResponse{}, ctx.Err()
						}
					}
					out := azureSessionResponse(fmt.Sprintf("CVE-page-%d", oldCalls))
					if operation == "finding pages" {
						if oldCalls == 1 {
							out.SkipToken = to.Ptr("page-two")
						} else if req.Options.SkipToken == nil || *req.Options.SkipToken != "page-two" {
							return out, fmt.Errorf("continuation token was lost")
						}
					}
					if operation == "empty findings fallback" && oldCalls == 1 {
						out.Data = []interface{}{}
						out.TotalRecords = to.Ptr[int64](0)
					}
					return out, nil
				}}
				var newCalls atomic.Int32
				a := NewAzureAdaptor()
				a.client, a.registryHost = oldClient, "old.azurecr.io"
				a.credProvider = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) { return nil, nil }
				a.clientFactory = func(azcore.TokenCredential, *arm.ClientOptions) (AzureAPI, error) {
					return &mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
						if *req.Query != "securityresources | limit 1" {
							newCalls.Add(1)
						}
						return azureSessionResponse("CVE-replacement"), nil
					}}, nil
				}
				images := []ContainerImageIdentifier{{Registry: "old.azurecr.io", Repository: "team/app", Hash: "sha256:abc"}}
				if operation == "status batch" {
					images = append(images, images[0])
				}
				completed := make(chan error, 1)
				go func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							completed <- fmt.Errorf("scan panicked: %v", recovered)
						}
					}()
					if operation == "status batch" {
						statuses, err := a.GetImagesScanStatus(ctx, images)
						if err == nil && (len(statuses) != 2 || !statuses[0].IsScanAvailable || !statuses[1].IsScanAvailable) {
							err = fmt.Errorf("status batch lost an available scan")
						}
						completed <- err
						return
					}
					reports, err := a.GetImagesVulnerabilities(ctx, images)
					if err == nil && (len(reports) != 1 || reports[0].Status != ScanStatusScanned) {
						err = fmt.Errorf("report lost scan availability")
					}
					if err == nil && operation == "finding pages" {
						vulns := reports[0].Vulnerabilities
						if len(vulns) != 2 || vulns[0].ID != "CVE-page-1" || vulns[1].ID != "CVE-page-2" {
							err = fmt.Errorf("findings crossed login sessions: %+v", vulns)
						}
					}
					completed <- err
				}()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("scan never reached the original client")
				}
				host := "old.azurecr.io"
				credentials := RegistryCredentials{}
				switch replacement {
				case "different registry":
					host = "new.azurecr.us"
				case "rejected login":
					credentials.Token = "unsupported"
				}
				err := a.Login(ctx, host, credentials)
				if replacement == "rejected login" {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				unblock.Do(func() { close(resume) })
				select {
				case err := <-completed:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("scan did not finish")
				}
				require.Equal(t, 2, oldCalls)
				require.Zero(t, newCalls.Load(), "a running batch must not use replacement credentials")
				images[0].Registry = host
				_, err = a.GetImagesScanStatus(ctx, images[:1])
				if replacement == "rejected login" {
					require.ErrorContains(t, err, "not initialized")
				} else {
					require.NoError(t, err)
					require.EqualValues(t, 1, newCalls.Load())
				}
			})
		}
	}
}

func TestAzureLoginProbeDoesNotPublishCandidateSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, resume := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(resume) })
	a := NewAzureAdaptor()
	a.credProvider = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) { return nil, nil }
	a.clientFactory = func(azcore.TokenCredential, *arm.ClientOptions) (AzureAPI, error) {
		return &mockAzureClient{resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			close(entered)
			select {
			case <-resume:
			case <-ctx.Done():
				return armresourcegraph.ClientResourcesResponse{}, ctx.Err()
			}
			return armresourcegraph.ClientResourcesResponse{}, nil
		}}, nil
	}
	completed := make(chan error, 1)
	go func() { completed <- a.Login(ctx, "new.azurecr.io", RegistryCredentials{}) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("probe did not start")
	}
	images := []ContainerImageIdentifier{{Registry: "new.azurecr.io", Repository: "app", Hash: "sha256:abc"}}
	_, err := a.GetImagesScanStatus(ctx, images)
	require.ErrorContains(t, err, "not initialized")
	_, err = a.GetImagesVulnerabilities(ctx, images)
	require.ErrorContains(t, err, "not initialized")
	_, err = a.GetImagesInformation(ctx, images)
	require.ErrorContains(t, err, "not initialized")
	unblock.Do(func() { close(resume) })
	require.NoError(t, <-completed)
}

func TestAzureConcurrentLoginAndScanMethods(t *testing.T) {
	a := NewAzureAdaptor()
	a.credProvider = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) { return nil, nil }
	a.clientFactory = func(azcore.TokenCredential, *arm.ClientOptions) (AzureAPI, error) {
		return &mockAzureClient{}, nil
	}
	ctx := context.Background()
	const host = "test.azurecr.io"
	// Digestless records avoid network pulls in GetImagesInformation.
	images := []ContainerImageIdentifier{{Registry: host, Repository: "app"}}
	require.NoError(t, a.Login(ctx, host, RegistryCredentials{}))
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Go(func() {
			for i := 0; i < 40; i++ {
				var err error
				switch worker {
				case 0:
					if i%2 == 0 {
						err = a.Login(ctx, host, RegistryCredentials{})
					} else if a.Login(ctx, host, RegistryCredentials{Token: "unsupported"}) == nil {
						t.Error("unsupported credentials were accepted")
					}
				case 1:
					_, err = a.GetImagesScanStatus(ctx, images)
				case 2:
					_, err = a.GetImagesVulnerabilities(ctx, images)
				case 3:
					_, err = a.GetImagesInformation(ctx, images)
				}
				if err != nil && !strings.Contains(err.Error(), "not initialized") {
					t.Errorf("unexpected concurrent error: %v", err)
				}
			}
		})
	}
	workers.Wait()
}

func TestAzureSessionStillRejectsForeignRegistry(t *testing.T) {
	var calls atomic.Int32
	a := &AzureAdaptor{registryHost: "owned.azurecr.io", client: &mockAzureClient{
		resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			calls.Add(1)
			return azureSessionResponse("unexpected"), nil
		},
	}}
	images := []ContainerImageIdentifier{{Registry: "foreign.azurecr.io", Repository: "app", Hash: "sha256:abc"}}
	_, err := a.GetImagesScanStatus(context.Background(), images)
	require.ErrorContains(t, err, "does not match logged-in registry")
	_, err = a.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorContains(t, err, "does not match logged-in registry")
	require.Zero(t, calls.Load(), "session snapshots must not weaken registry validation")
}
