package imagescan

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/require"
)

func destroyedECRImage() ContainerImageIdentifier {
	return ContainerImageIdentifier{Registry: "111111111111.dkr.ecr.us-east-1.amazonaws.com", Repository: "app", Tag: "release"}
}

func requireECRSessionDestroyed(t *testing.T, adaptor *AWSECRAdaptor) {
	t.Helper()
	images := []ContainerImageIdentifier{destroyedECRImage()}
	_, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.ErrorContains(t, err, "not initialized")
	_, err = adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorContains(t, err, "not initialized")
	_, err = adaptor.GetImagesInformation(context.Background(), images)
	require.ErrorContains(t, err, "not initialized")
}

func TestECRDestroyInvalidatesSessionAndAllowsNewLogin(t *testing.T) {
	api := &mockECRClient{describeFindingsFunc: func(context.Context, *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		t.Error("destroyed session made an API request")
		return &ecr.DescribeImageScanFindingsOutput{}, nil
	}}
	adaptor := NewAWSECRAdaptor()
	adaptor.client = api
	require.NoError(t, adaptor.Destroy())
	require.NoError(t, adaptor.Destroy())
	requireECRSessionDestroyed(t, adaptor)
	adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, nil
	}
	adaptor.clientFactory = func(aws.Config) ECRAPI { return api }
	require.NoError(t, adaptor.Login(context.Background(), destroyedECRImage().Registry, RegistryCredentials{}))
	infos, err := adaptor.GetImagesInformation(context.Background(), []ContainerImageIdentifier{destroyedECRImage()})
	require.NoError(t, err)
	require.Len(t, infos, 1)
	require.NoError(t, adaptor.Destroy())
	requireECRSessionDestroyed(t, adaptor)
}

func TestECRDestroyPreservesInFlightPagination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	defer unblock()
	calls := 0
	api := &mockECRClient{describeFindingsFunc: func(ctx context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		calls++
		if calls == 1 {
			close(entered)
			select {
			case <-resume:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else if aws.ToString(input.NextToken) != "next" {
			return nil, fmt.Errorf("lost next-page token")
		}
		out := &ecr.DescribeImageScanFindingsOutput{
			ImageScanStatus:   &types.ImageScanStatus{Status: types.ScanStatusComplete},
			ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{{Name: aws.String(fmt.Sprintf("CVE-%d", calls))}}},
		}
		if calls == 1 {
			out.NextToken = aws.String("next")
		}
		return out, nil
	}}
	adaptor := NewAWSECRAdaptor()
	adaptor.client = api
	type outcome struct {
		reports []ContainerImageVulnerabilityReport
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		reports, err := adaptor.GetImagesVulnerabilities(ctx, []ContainerImageIdentifier{destroyedECRImage()})
		done <- outcome{reports, err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("scan did not start")
	}
	require.NoError(t, adaptor.Destroy())
	requireECRSessionDestroyed(t, adaptor)
	unblock()
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Len(t, result.reports, 1)
		require.Len(t, result.reports[0].Vulnerabilities, 2)
		require.Equal(t, ScanStatusScanned, result.reports[0].Status)
	case <-ctx.Done():
		t.Fatal("in-flight scan did not finish")
	}
	require.Equal(t, 2, calls)
}

func TestECRDestroyWaitsForPendingLoginPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	defer unblock()
	adaptor := NewAWSECRAdaptor()
	adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
		close(entered)
		select {
		case <-resume:
			return aws.Config{}, nil
		case <-ctx.Done():
			return aws.Config{}, ctx.Err()
		}
	}
	adaptor.clientFactory = func(aws.Config) ECRAPI { return &mockECRClient{} }
	loginDone := make(chan error, 1)
	go func() { loginDone <- adaptor.Login(ctx, destroyedECRImage().Registry, RegistryCredentials{}) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("login did not start")
	}
	destroyStarted, destroyDone := make(chan struct{}), make(chan error, 1)
	go func() { close(destroyStarted); destroyDone <- adaptor.Destroy() }()
	<-destroyStarted
	// Teardown must not return while the earlier login can still publish.
	select {
	case err := <-destroyDone:
		require.NoError(t, err)
		t.Fatal("Destroy returned before pending login finished")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-loginDone:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("login did not finish")
	}
	select {
	case err := <-destroyDone:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("Destroy did not finish")
	}
	requireECRSessionDestroyed(t, adaptor)
}

func TestECRDestroyZeroValueIsSafe(t *testing.T) {
	adaptor := &AWSECRAdaptor{}
	require.NoError(t, adaptor.Destroy())
	require.NoError(t, adaptor.Destroy())
	requireECRSessionDestroyed(t, adaptor)
}

func TestECRDestroyPreservesInFlightStatusBatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	defer unblock()
	calls := 0
	api := &mockECRClient{describeFindingsFunc: func(ctx context.Context, _ *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		calls++
		if calls == 1 {
			close(entered)
			select {
			case <-resume:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &ecr.DescribeImageScanFindingsOutput{ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete}}, nil
	}}
	adaptor := NewAWSECRAdaptor()
	adaptor.client = api
	type outcome struct {
		statuses []ContainerImageScanStatus
		err      error
	}
	done := make(chan outcome, 1)
	images := []ContainerImageIdentifier{destroyedECRImage(), destroyedECRImage()}
	go func() { statuses, err := adaptor.GetImagesScanStatus(ctx, images); done <- outcome{statuses, err} }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("status batch did not start")
	}
	require.NoError(t, adaptor.Destroy())
	requireECRSessionDestroyed(t, adaptor)
	unblock()
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Len(t, result.statuses, 2)
		for _, status := range result.statuses {
			require.True(t, status.IsScanAvailable)
		}
	case <-ctx.Done():
		t.Fatal("status batch did not finish")
	}
	require.Equal(t, 2, calls)
}
