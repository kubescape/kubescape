package imagescan

import (
	"context"
	"errors"
	"testing"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/stretchr/testify/require"
)

func TestGCPFailedReloginInvalidatesSession(t *testing.T) {
	for _, stage := range []string{"credentials", "registry", "factory", "probe"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			adaptor := NewGCPAdaptor()
			providerErr := errors.New("fixture provider failure")
			failAt := ""
			var clients []*containeranalysis.Client
			var apis []*mockGCPClient
			adaptor.clientFactory = func(context.Context) (*containeranalysis.Client, error) {
				if failAt == "factory" {
					return nil, providerErr
				}
				c := newFakeContainerAnalysisClient(t)
				clients = append(clients, c)
				return c, nil
			}
			adaptor.apiFactory = func(*containeranalysis.Client) GCPAPI {
				api := &mockGCPClient{}
				if failAt == "probe" {
					api.mockErr = providerErr
				}
				apis = append(apis, api)
				return api
			}
			require.NoError(t, adaptor.Login(ctx, "us-docker.pkg.dev/old-project/repo", RegistryCredentials{}))
			require.NotNil(t, adaptor.client)
			oldAPI := apis[0]
			oldAPI.lastReq = nil

			failAt = stage
			registry := "us-docker.pkg.dev/new-project/repo"
			credentials := RegistryCredentials{}
			if stage == "credentials" {
				credentials.Token = "unsupported"
			}
			if stage == "registry" {
				registry = "not-a-gcp-registry"
			}
			err := adaptor.Login(ctx, registry, credentials)
			require.Error(t, err)
			if stage == "factory" || stage == "probe" {
				require.ErrorIs(t, err, providerErr)
			}

			// The session of the earlier login must be gone, not just unused.
			images := []ContainerImageIdentifier{{Registry: "us-docker.pkg.dev", Repository: "old-project/repo/app", Hash: "sha256:abc"}}
			statuses, err := adaptor.GetImagesScanStatus(ctx, images)
			require.ErrorContains(t, err, "client not initialized")
			require.Nil(t, statuses)
			reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
			require.ErrorContains(t, err, "client not initialized")
			require.Nil(t, reports)
			infos, err := adaptor.GetImagesInformation(ctx, images)
			require.ErrorContains(t, err, "client not initialized")
			require.Nil(t, infos)
			require.Nil(t, oldAPI.lastReq, "failed login must not leave the old client callable")
			require.Nil(t, adaptor.client)
			require.Nil(t, adaptor.owningClient)
			require.Error(t, clients[0].Close(), "the old client should already be closed")

			// A later successful login works against the new project.
			failAt = ""
			require.NoError(t, adaptor.Login(ctx, "us-docker.pkg.dev/new-project/repo", RegistryCredentials{}))
			images = []ContainerImageIdentifier{{Registry: "us-docker.pkg.dev", Repository: "new-project/repo/app", Hash: "sha256:abc"}}
			statuses, err = adaptor.GetImagesScanStatus(ctx, images)
			require.NoError(t, err)
			require.Len(t, statuses, 1)
			newAPI := apis[len(apis)-1]
			require.Equal(t, "projects/new-project", newAPI.lastReq.GetParent())
			require.NoError(t, adaptor.Destroy())
		})
	}
}
