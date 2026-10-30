package imagescan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/stretchr/testify/require"
)

func TestAzureFailedProbePreservesActiveBatch(t *testing.T) {
	for _, operation := range []string{"finding pages", "empty findings fallback"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			entered, resume := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(resume) })
			defer unblock()
			oldCalls := 0
			oldClient := &mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				oldCalls++
				if !strings.Contains(*req.Query, `registryName =~ "old"`) {
					return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("active batch changed registry")
				}
				if oldCalls == 1 {
					close(entered)
					select {
					case <-resume:
					case <-ctx.Done():
						return armresourcegraph.ClientResourcesResponse{}, ctx.Err()
					}
				}
				out := azureSessionResponse(fmt.Sprintf("CVE-old-%d", oldCalls))
				if oldCalls == 1 && operation == "finding pages" {
					next := "old-page-two"
					out.SkipToken = &next
				} else if oldCalls == 2 && operation == "finding pages" {
					if req.Options.SkipToken == nil || *req.Options.SkipToken != "old-page-two" {
						return out, fmt.Errorf("continuation token changed")
					}
				} else if oldCalls == 1 {
					out.Data = []any{}
				}
				return out, nil
			}}
			probeErr := errors.New("replacement identity probe rejected")
			probeCalls := 0
			a := NewAzureAdaptor()
			a.client, a.registryHost = oldClient, "old.azurecr.io"
			a.credProvider = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) { return nil, nil }
			a.clientFactory = func(azcore.TokenCredential, *arm.ClientOptions) (AzureAPI, error) {
				return &mockAzureClient{resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
					probeCalls++
					require.Equal(t, "securityresources | limit 1", *req.Query)
					return armresourcegraph.ClientResourcesResponse{}, probeErr
				}}, nil
			}
			images := []ContainerImageIdentifier{{Registry: "old.azurecr.io", Repository: "app", Hash: "sha256:abc"}}
			completed := make(chan error, 1)
			go func() {
				reports, err := a.GetImagesVulnerabilities(ctx, images)
				if err == nil && (len(reports) != 1 || reports[0].Status != ScanStatusScanned) {
					err = fmt.Errorf("active report lost discovery status")
				}
				if err == nil && operation == "finding pages" && (len(reports[0].Vulnerabilities) != 2 || reports[0].Vulnerabilities[1].ID != "CVE-old-2") {
					err = fmt.Errorf("active report lost original-session findings")
				}
				completed <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("active batch did not start")
			}
			require.ErrorIs(t, a.Login(ctx, "new.azurecr.us", RegistryCredentials{}), probeErr)
			require.Equal(t, 1, probeCalls)
			_, err := a.GetImagesScanStatus(ctx, images)
			require.ErrorContains(t, err, "not initialized")
			_, err = a.GetImagesVulnerabilities(ctx, images)
			require.ErrorContains(t, err, "not initialized")
			_, err = a.GetImagesInformation(ctx, images)
			require.ErrorContains(t, err, "not initialized")
			unblock()
			select {
			case err := <-completed:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("active batch did not finish")
			}
			require.Equal(t, 2, oldCalls)
			require.Equal(t, 1, probeCalls, "failed candidate must never be used for a scan")
		})
	}
}
