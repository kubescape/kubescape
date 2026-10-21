package imagescan

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/stretchr/testify/require"
)

func TestAzureFailedReloginInvalidatesSession(t *testing.T) {
	for _, stage := range []string{"credentials", "registry", "identity", "factory", "probe"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			adaptor := NewAzureAdaptor()
			calls := 0
			providerErr := errors.New("fixture provider failure")
			failAt := ""
			adaptor.credProvider = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
				if failAt == "identity" {
					return nil, providerErr
				}
				return nil, nil
			}
			adaptor.clientFactory = func(azcore.TokenCredential, *arm.ClientOptions) (AzureAPI, error) {
				if failAt == "factory" {
					return nil, providerErr
				}
				return &mockAzureClient{resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
					calls++
					if failAt == "probe" {
						return armresourcegraph.ClientResourcesResponse{}, providerErr
					}
					return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
						TotalRecords: to.Ptr[int64](1),
					}}, nil
				}}, nil
			}
			require.NoError(t, adaptor.Login(ctx, "old.azurecr.io", RegistryCredentials{}))
			require.NotNil(t, adaptor.client)

			failAt = stage
			registry := "new.azurecr.us"
			credentials := RegistryCredentials{}
			if stage == "credentials" {
				credentials.Username = "unsupported"
			}
			if stage == "registry" {
				registry = "not-an-azure-registry.example"
			}
			err := adaptor.Login(ctx, registry, credentials)
			require.Error(t, err)
			if stage == "identity" || stage == "factory" || stage == "probe" {
				require.ErrorIs(t, err, providerErr)
			}
			callsAfterLogin := calls
			// Neither the old registry nor the attempted registry may use a
			// credential/client left over from either login attempt.
			for _, host := range []string{"old.azurecr.io", "new.azurecr.us"} {
				images := []ContainerImageIdentifier{{Registry: host, Repository: "team/app", Hash: "sha256:abc"}}
				statuses, err := adaptor.GetImagesScanStatus(ctx, images)
				require.ErrorContains(t, err, "client not initialized")
				require.Nil(t, statuses)
				reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
				require.ErrorContains(t, err, "client not initialized")
				require.Nil(t, reports)
				infos, err := adaptor.GetImagesInformation(ctx, images)
				require.ErrorContains(t, err, "client not initialized")
				require.Nil(t, infos)
			}
			require.Equal(t, callsAfterLogin, calls, "failed login must not leave a callable provider")
			require.Nil(t, adaptor.client)
			require.Empty(t, adaptor.registryHost)

			// A later successful login restores operation for the new target.
			failAt = ""
			require.NoError(t, adaptor.Login(ctx, "new.azurecr.us", RegistryCredentials{}))
			require.Equal(t, "new.azurecr.us", adaptor.registryHost)
			images := []ContainerImageIdentifier{{Registry: "new.azurecr.us", Repository: "team/app", Hash: "sha256:abc"}}
			statuses, err := adaptor.GetImagesScanStatus(ctx, images)
			require.NoError(t, err)
			require.Len(t, statuses, 1)
			require.True(t, statuses[0].IsScanAvailable)
		})
	}
}

func TestAzureFirstLoginProbeFailureLeavesNoSession(t *testing.T) {
	adaptor := NewAzureAdaptor()
	adaptor.credProvider = func(*azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
		return nil, nil
	}
	adaptor.clientFactory = func(azcore.TokenCredential, *arm.ClientOptions) (AzureAPI, error) {
		return &mockAzureClient{resourcesOut: func(armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			return armresourcegraph.ClientResourcesResponse{}, context.DeadlineExceeded
		}}, nil
	}
	err := adaptor.Login(context.Background(), "first.azurecr.io", RegistryCredentials{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, adaptor.client)
	require.Empty(t, adaptor.registryHost)
}
