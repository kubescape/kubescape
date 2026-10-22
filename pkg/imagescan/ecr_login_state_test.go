package imagescan

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/require"
)

func TestECRFailedReloginInvalidatesSession(t *testing.T) {
	const oldRegistry = "111111111111.dkr.ecr.us-east-1.amazonaws.com"
	const newRegistry = "222222222222.dkr.ecr.eu-west-1.amazonaws.com"
	configErr := errors.New("configuration unavailable")
	for _, stage := range []string{"username", "password", "token", "registry", "config", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			adaptor := NewAWSECRAdaptor()
			failConfig := false
			configCalls, factoryCalls := 0, 0
			oldCalls, newCalls := 0, 0
			adaptor.configProvider = func(ctx context.Context, options ...func(*config.LoadOptions) error) (aws.Config, error) {
				configCalls++
				if err := ctx.Err(); err != nil {
					return aws.Config{}, err
				}
				if failConfig {
					return aws.Config{}, configErr
				}
				var opts config.LoadOptions
				for _, apply := range options {
					require.NoError(t, apply(&opts))
				}
				return aws.Config{Region: opts.Region}, nil
			}
			adaptor.clientFactory = func(cfg aws.Config) ECRAPI {
				factoryCalls++
				return &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
					if cfg.Region == "us-east-1" {
						oldCalls++
					} else {
						require.Equal(t, "eu-west-1", cfg.Region)
						newCalls++
						require.Equal(t, "222222222222", aws.ToString(input.RegistryId))
					}
					return &ecr.DescribeImageScanFindingsOutput{
						ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
						ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{{
							Name: aws.String("CVE-fixture"), Severity: types.FindingSeverityHigh,
						}}},
					}, nil
				}}
			}
			ctx := context.Background()
			require.NoError(t, adaptor.Login(ctx, oldRegistry, RegistryCredentials{}))
			images := []ContainerImageIdentifier{{Registry: oldRegistry, Repository: "team/app", Tag: "release"}}
			statuses, err := adaptor.GetImagesScanStatus(ctx, images)
			require.NoError(t, err)
			require.True(t, statuses[0].IsScanAvailable)
			require.Equal(t, 1, oldCalls, "establish that the previous session is usable")

			credentials := RegistryCredentials{}
			registry := newRegistry
			loginCtx := ctx
			switch stage {
			case "username":
				credentials.Username = "unsupported"
			case "password":
				credentials.Password = "unsupported"
			case "token":
				credentials.Token = "unsupported"
			case "registry":
				registry = "not-an-ecr-registry.example"
			case "config":
				failConfig = true
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				loginCtx = cancelled
			}
			err = adaptor.Login(loginCtx, registry, credentials)
			require.Error(t, err)
			if stage == "config" {
				require.ErrorIs(t, err, configErr)
			} else if stage == "cancelled" {
				require.ErrorIs(t, err, context.Canceled)
			}
			configsAfterFailure := configCalls
			require.Equal(t, 1, factoryCalls, "a failed login must not create a replacement client")

			// Both real and empty batches must respect the failed session,
			// even if the caller asks about the previously working registry.
			for _, host := range []string{oldRegistry, newRegistry} {
				for _, batch := range [][]ContainerImageIdentifier{nil, {{Registry: host, Repository: "team/app", Tag: "release"}}} {
					statuses, err := adaptor.GetImagesScanStatus(ctx, batch)
					require.ErrorContains(t, err, "client not initialized")
					require.Nil(t, statuses)
					reports, err := adaptor.GetImagesVulnerabilities(ctx, batch)
					require.ErrorContains(t, err, "client not initialized")
					require.Nil(t, reports)
					infos, err := adaptor.GetImagesInformation(ctx, batch)
					require.ErrorContains(t, err, "client not initialized")
					require.Nil(t, infos)
				}
			}
			require.Nil(t, adaptor.client)
			require.Equal(t, 1, oldCalls, "failed login must not reuse old credentials for scanning")
			require.Zero(t, newCalls)
			require.Equal(t, configsAfterFailure, configCalls, "scan methods must not silently log in again")

			// An explicit successful login is the only way to restore scanning.
			failConfig = false
			require.NoError(t, adaptor.Login(ctx, newRegistry, RegistryCredentials{}))
			require.Equal(t, 2, factoryCalls)
			images[0].Registry = newRegistry
			statuses, err = adaptor.GetImagesScanStatus(ctx, images)
			require.NoError(t, err)
			require.True(t, statuses[0].IsScanAvailable)
			reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
			require.NoError(t, err)
			require.Len(t, reports, 1)
			require.Len(t, reports[0].Vulnerabilities, 1)
			require.Equal(t, "CVE-fixture", reports[0].Vulnerabilities[0].ID)
			infos, err := adaptor.GetImagesInformation(ctx, images)
			require.NoError(t, err)
			require.Len(t, infos, 1)
			require.Equal(t, images[0], infos[0].ImageID)
			require.Equal(t, 1, oldCalls)
			require.Equal(t, 2, newCalls)
		})
	}
}

func TestECRFirstLoginFailureDoesNotCreateSession(t *testing.T) {
	adaptor := NewAWSECRAdaptor()
	providerErr := errors.New("no AWS configuration")
	adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, providerErr
	}
	adaptor.clientFactory = func(aws.Config) ECRAPI {
		t.Fatal("failed configuration must not reach the client factory")
		return nil
	}
	err := adaptor.Login(context.Background(), "111111111111.dkr.ecr.us-east-1.amazonaws.com", RegistryCredentials{})
	require.ErrorIs(t, err, providerErr)
	require.Nil(t, adaptor.client)
	images := []ContainerImageIdentifier{{Registry: "111111111111.dkr.ecr.us-east-1.amazonaws.com", Repository: "app", Tag: "release"}}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.ErrorContains(t, err, "client not initialized")
	require.Nil(t, statuses)
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorContains(t, err, "client not initialized")
	require.Nil(t, reports)
}

func TestECRSuccessfulReloginReplacesSession(t *testing.T) {
	adaptor := NewAWSECRAdaptor()
	factories := 0
	adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, nil
	}
	adaptor.clientFactory = func(aws.Config) ECRAPI {
		factories++
		generation := factories
		return &mockECRClient{describeFindingsFunc: func(context.Context, *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			require.Equal(t, 2, generation, "only the latest successful session should perform requests")
			return &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
			}, nil
		}}
	}
	ctx := context.Background()
	const registry = "111111111111.dkr.ecr.us-east-1.amazonaws.com"
	require.NoError(t, adaptor.Login(ctx, registry, RegistryCredentials{}))
	require.NoError(t, adaptor.Login(ctx, registry, RegistryCredentials{}))
	require.Equal(t, 2, factories)
	statuses, err := adaptor.GetImagesScanStatus(ctx, []ContainerImageIdentifier{{Registry: registry, Repository: "app", Tag: "release"}})
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.True(t, statuses[0].IsScanAvailable)
}

func TestECRRejectedLoginDoesNotLoadDefaultCredentials(t *testing.T) {
	for _, registry := range []string{"not-ecr.example", "111111111111.dkr.ecr.us-east-1.amazonaws.com"} {
		t.Run(registry, func(t *testing.T) {
			adaptor := NewAWSECRAdaptor()
			adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
				t.Fatal("input rejection must not start default credential discovery")
				return aws.Config{}, nil
			}
			credentials := RegistryCredentials{}
			if registry != "not-ecr.example" {
				credentials.Token = "unsupported"
			}
			require.Error(t, adaptor.Login(context.Background(), registry, credentials))
			require.Nil(t, adaptor.client)
		})
	}
}
