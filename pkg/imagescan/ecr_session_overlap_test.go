package imagescan

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/require"
)

func TestECRScanRetainsSessionDuringRelogin(t *testing.T) {
	for _, operation := range []string{"status batch", "vulnerability pages"} {
		for _, replacement := range []string{"rejected", "successful"} {
			t.Run(operation+"/"+replacement, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				entered := make(chan struct{})
				resume := make(chan struct{})
				var unblock sync.Once
				defer unblock.Do(func() { close(resume) })
				calls := 0
				oldClient := &mockECRClient{describeFindingsFunc: func(ctx context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
					calls++
					if calls == 1 {
						close(entered)
						select {
						case <-resume:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					out := &ecr.DescribeImageScanFindingsOutput{
						ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
						ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{{
							Name: aws.String(fmt.Sprintf("CVE-page-%d", calls)),
						}}},
					}
					if operation == "vulnerability pages" && calls == 1 {
						out.NextToken = aws.String("second-page")
					}
					if operation == "vulnerability pages" && calls == 2 && aws.ToString(input.NextToken) != "second-page" {
						return nil, fmt.Errorf("second page lost its continuation token")
					}
					return out, nil
				}}
				newCalls := 0
				adaptor := NewAWSECRAdaptor()
				adaptor.client = oldClient
				adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
					return aws.Config{}, nil
				}
				adaptor.clientFactory = func(aws.Config) ECRAPI {
					return &mockECRClient{describeFindingsFunc: func(context.Context, *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
						newCalls++
						return &ecr.DescribeImageScanFindingsOutput{}, nil
					}}
				}
				images := []ContainerImageIdentifier{{Registry: "111111111111.dkr.ecr.us-east-1.amazonaws.com", Repository: "app", Tag: "release"}}
				if operation == "status batch" {
					images = append(images, images[0])
				}
				completed := make(chan error, 1)
				go func() {
					// Report a panic as a regression failure instead of crashing the
					// test process when run against the earlier implementation.
					defer func() {
						if recovered := recover(); recovered != nil {
							completed <- fmt.Errorf("in-flight scan panicked: %v", recovered)
						}
					}()
					if operation == "status batch" {
						statuses, err := adaptor.GetImagesScanStatus(ctx, images)
						if err == nil && (len(statuses) != 2 || !statuses[0].IsScanAvailable || !statuses[1].IsScanAvailable) {
							err = fmt.Errorf("status batch did not finish on its original session")
						}
						completed <- err
					} else {
						reports, err := adaptor.GetImagesVulnerabilities(ctx, images)
						if err == nil && (len(reports) != 1 || len(reports[0].Vulnerabilities) != 2) {
							err = fmt.Errorf("paginated report lost findings across session replacement")
						}
						completed <- err
					}
				}()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("scan did not reach its first API call")
				}
				credentials := RegistryCredentials{}
				if replacement == "rejected" {
					credentials.Token = "unsupported"
				}
				err := adaptor.Login(ctx, images[0].Registry, credentials)
				if replacement == "rejected" {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				unblock.Do(func() { close(resume) })
				select {
				case err := <-completed:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("scan did not finish after re-login")
				}
				require.Equal(t, 2, calls)
				require.Zero(t, newCalls, "an existing scan must never switch AWS sessions mid-operation")
				_, err = adaptor.GetImagesScanStatus(ctx, images[:1])
				if replacement == "rejected" {
					require.ErrorContains(t, err, "client not initialized")
				} else {
					require.NoError(t, err)
					require.Equal(t, 1, newCalls, "new scans use the replacement session")
				}
			})
		}
	}
}

func TestECRConcurrentLoginAndScanMethods(t *testing.T) {
	adaptor := NewAWSECRAdaptor()
	adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, nil
	}
	adaptor.clientFactory = func(aws.Config) ECRAPI {
		return &mockECRClient{describeFindingsFunc: func(context.Context, *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			return &ecr.DescribeImageScanFindingsOutput{}, nil
		}}
	}
	ctx := context.Background()
	const registry = "111111111111.dkr.ecr.us-east-1.amazonaws.com"
	images := []ContainerImageIdentifier{{Registry: registry, Repository: "app", Tag: "release"}}
	require.NoError(t, adaptor.Login(ctx, registry, RegistryCredentials{}))
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Go(func() {
			for i := 0; i < 50; i++ {
				var err error
				switch worker {
				case 0:
					if i%2 == 0 {
						if adaptor.Login(ctx, registry, RegistryCredentials{Token: "unsupported"}) == nil {
							t.Error("unsupported credentials were accepted")
						}
					} else {
						err = adaptor.Login(ctx, registry, RegistryCredentials{})
					}
				case 1:
					_, err = adaptor.GetImagesScanStatus(ctx, images)
				case 2:
					_, err = adaptor.GetImagesVulnerabilities(ctx, images)
				case 3:
					_, err = adaptor.GetImagesInformation(ctx, images)
				}
				if err != nil && !strings.Contains(err.Error(), "client not initialized") {
					t.Errorf("unexpected concurrent operation error: %v", err)
				}
			}
		})
	}
	workers.Wait()
}
