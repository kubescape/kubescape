package imagescan

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/stretchr/testify/require"
)

func TestAzureReloginWaitsForActiveScan(t *testing.T) {
	for _, operation := range []string{"status batch", "vulnerability pages"} {
		for _, failure := range []string{"credentials", "probe", "none"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				func(t *testing.T) {
					entered, resume := make(chan struct{}), make(chan struct{})
					oldCalls := 0
					oldAPI := &mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
						oldCalls++
						if oldCalls == 1 {
							close(entered)
							<-resume
						}
						if !strings.Contains(*req.Query, `registryName =~ "old"`) {
							t.Errorf("active query lost its registry identity: %s", *req.Query)
						}
						if operation == "status batch" {
							return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{TotalRecords: to.Ptr[int64](1)}}, nil
						}
						response := armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
							Data: []any{map[string]any{"id": fmt.Sprintf("CVE-old-%d", oldCalls)}},
						}}
						if oldCalls == 1 {
							response.SkipToken = to.Ptr("old-page-2")
						} else if skipToken := req.Options.SkipToken; skipToken == nil || *skipToken != "old-page-2" {
							t.Error("second page lost its continuation token")
						}
						return response, nil
					}}
					adaptor := NewAzureAdaptor()
					adaptor.client, adaptor.registryHost = oldAPI, "old.azurecr.io"
					adaptor.credProvider = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) { return nil, nil }
					adaptor.clientFactory = func(azcore.TokenCredential, *arm.ClientOptions) (AzureAPI, error) {
						return &mockAzureClient{resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
							if failure == "probe" {
								return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("probe rejected")
							}
							return armresourcegraph.ClientResourcesResponse{}, nil
						}}, nil
					}
					images := []ContainerImageIdentifier{{Registry: "old.azurecr.io", Repository: "app", Hash: "sha256:123"}}
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
							if err == nil && (len(statuses) != 2 || !statuses[1].IsScanAvailable) {
								err = fmt.Errorf("active batch lost an image's scan status")
							}
							scanDone <- err
						} else {
							reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
							if err == nil && (len(reports) != 1 || len(reports[0].Vulnerabilities) != 2) {
								err = fmt.Errorf("active report switched sessions between pages")
							}
							scanDone <- err
						}
					}()
					<-entered
					loginDone := make(chan error, 1)
					go func() {
						credentials := RegistryCredentials{}
						if failure == "credentials" {
							credentials.Token = "unsupported"
						}
						loginDone <- adaptor.Login(context.Background(), "new.azurecr.io", credentials)
					}()
					var loginErr error
					early := false
					select {
					case loginErr = <-loginDone:
						early = true
						t.Error("login replaced a session still used by a scan")
					case <-time.After(30 * time.Millisecond):
					}
					close(resume)
					select {
					case err := <-scanDone:
						require.NoError(t, err)
					case <-time.After(5 * time.Second):
						t.Fatal("active scan did not finish after release")
					}
					if !early {
						select {
						case loginErr = <-loginDone:
						case <-time.After(5 * time.Second):
							t.Fatal("login did not finish after scan")
						}
					}
					require.Equal(t, 2, oldCalls)
					if failure == "none" {
						require.NoError(t, loginErr)
						images[0].Registry = "new.azurecr.io"
						_, err := adaptor.GetImagesScanStatus(context.Background(), images[:1])
						require.NoError(t, err)
						images[0].Registry = "old.azurecr.io"
						_, err = adaptor.GetImagesScanStatus(context.Background(), images[:1])
						require.ErrorContains(t, err, "does not match logged-in registry")
					} else {
						require.Error(t, loginErr)
						_, err := adaptor.GetImagesVulnerabilities(context.Background(), images[:1])
						require.ErrorContains(t, err, "client not initialized")
					}
				}(t)
			})
		}
	}
}

func TestAzureConcurrentLoginAndReadMethods(t *testing.T) {
	adaptor := NewAzureAdaptor()
	adaptor.credProvider = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) { return nil, nil }
	adaptor.clientFactory = func(azcore.TokenCredential, *arm.ClientOptions) (AzureAPI, error) {
		return &mockAzureClient{}, nil
	}
	ctx := context.Background()
	require.NoError(t, adaptor.Login(ctx, "old.azurecr.io", RegistryCredentials{}))
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Go(func() {
			for i := 0; i < 30; i++ {
				var err error
				switch worker {
				case 0:
					err = adaptor.Login(ctx, "new.azurecr.io", RegistryCredentials{})
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

func TestAzureSessionAllowsConcurrentScans(t *testing.T) {
	entered, resume := make(chan struct{}, 2), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	defer unblock()
	adaptor := &AzureAdaptor{registryHost: "registry.azurecr.io", client: &mockAzureClient{
		resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			entered <- struct{}{}
			<-resume
			return armresourcegraph.ClientResourcesResponse{}, nil
		},
	}}
	images := []ContainerImageIdentifier{{Registry: "registry.azurecr.io", Repository: "app", Hash: "sha256:123"}}
	done := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := adaptor.GetImagesScanStatus(context.Background(), images)
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
