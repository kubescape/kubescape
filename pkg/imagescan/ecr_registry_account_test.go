package imagescan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECRRegistryAccount(t *testing.T) {
	for _, tt := range []struct {
		registry string
		account  string
	}{
		{"123456789012.dkr.ecr.us-east-1.amazonaws.com", "123456789012"},
		{"000000000001.dkr.ecr.eu-west-1.amazonaws.com", "000000000001"},
		{"999999999999.dkr.ecr.us-gov-west-1.amazonaws.com", "999999999999"},
		{"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn", "123456789012"},
		{"123456789012.dkr.ecr-fips.us-east-1.amazonaws.com", "123456789012"},
		{"123456789012.dkr-ecr.us-east-1.on.aws", "123456789012"},
		{"123456789012.dkr-ecr-fips.us-east-1.on.aws", "123456789012"},
	} {
		t.Run(tt.registry, func(t *testing.T) {
			account, err := ecrRegistryAccount(tt.registry)
			require.NoError(t, err)
			assert.Equal(t, tt.account, account)
		})
	}
}

func TestECRRegistryAccountRejectsAmbiguousOwner(t *testing.T) {
	for _, registry := range []string{
		"",
		"public.ecr.aws",
		"docker.io",
		"12345.dkr.ecr.us-east-1.amazonaws.com",
		"1234567890123.dkr.ecr.us-east-1.amazonaws.com",
		"12345678901x.dkr.ecr.us-east-1.amazonaws.com",
		"123456789012.dkr.ecr..amazonaws.com",
		"123456789012.dkr.other.us-east-1.amazonaws.com",
		"123456789012.other.ecr.us-east-1.amazonaws.com",
		"123456789012.dkr.ecr.us-east-1.example.com",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com.evil",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com.cn.evil",
		"https://123456789012.dkr.ecr.us-east-1.amazonaws.com",
		"123456789012.dkr.ecr.us-east-1.amazonaws.com/repo",
		"12345.dkr-ecr.us-east-1.on.aws",
		"12345678901x.dkr-ecr-fips.us-east-1.on.aws",
		"1234567890123.dkr-ecr.us-east-1.on.aws",
		"123456789012.dkr-ecr..on.aws",
		"123456789012.dkr-ecr-fips..on.aws",
		"123456789012.dkr-other.us-east-1.on.aws",
		"123456789012.dkr-ecr.us-east-1.on.aws.evil",
		"123456789012.dkr-ecr-fips.us-east-1.on.example",
		"https://123456789012.dkr-ecr.us-east-1.on.aws",
		"123456789012.dkr-ecr.us-east-1.on.aws/repo",
	} {
		t.Run(registry, func(t *testing.T) {
			account, err := ecrRegistryAccount(registry)
			require.Error(t, err)
			assert.Empty(t, account)
		})
	}
}

func TestECRAccountSelection_StatusQueriesImageOwner(t *testing.T) {
	// Both accounts contain the same repository and tag. A request without
	// RegistryId would return the caller account's queued scan, not the
	// completed scan for the image actually running in the workload.
	image := ContainerImageIdentifier{
		Registry:   "222222222222.dkr.ecr.us-east-1.amazonaws.com",
		Repository: "shared/application", Tag: "release",
	}
	completed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	requests := 0
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		requests++
		assert.Equal(t, image.Repository, aws.ToString(input.RepositoryName))
		assert.Equal(t, image.Tag, aws.ToString(input.ImageId.ImageTag))
		assert.Equal(t, int32(1), aws.ToInt32(input.MaxResults))
		if aws.ToString(input.RegistryId) != "222222222222" {
			return &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusPending},
			}, nil
		}
		return &ecr.DescribeImageScanFindingsOutput{
			ImageScanStatus:   &types.ImageScanStatus{Status: types.ScanStatusComplete},
			ImageScanFindings: &types.ImageScanFindings{ImageScanCompletedAt: &completed},
		}, nil
	}}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, 1, requests)
	assert.Equal(t, image, statuses[0].ImageID)
	assert.Equal(t, ScanStatusScanned, statuses[0].Status)
	assert.True(t, statuses[0].IsScanAvailable)
	assert.Equal(t, completed, statuses[0].LastScanDate)
}

func TestECRAccountSelection_VulnerabilitiesCannotComeFromCallerAccount(t *testing.T) {
	image := ContainerImageIdentifier{
		Registry:   "222222222222.dkr.ecr.us-east-1.amazonaws.com",
		Repository: "shared/application", Tag: "release",
	}
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		if aws.ToString(input.RegistryId) != "222222222222" {
			// The credentials' account has a clean image with this tag.
			return &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
			}, nil
		}
		return &ecr.DescribeImageScanFindingsOutput{
			ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
			ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{
				{Name: aws.String("CVE-IMAGE-OWNER"), Severity: types.FindingSeverityCritical},
			}},
		}, nil
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, reports, 1)
	assert.Equal(t, image, reports[0].ImageID)
	assert.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Len(t, reports[0].Vulnerabilities, 1)
	assert.Equal(t, "CVE-IMAGE-OWNER", reports[0].Vulnerabilities[0].ID)
	assert.Equal(t, "Critical", reports[0].Vulnerabilities[0].Severity)
}

func TestECRAccountSelection_EveryPageKeepsAccountAndDigest(t *testing.T) {
	image := ContainerImageIdentifier{
		Registry:   "222222222222.dkr.ecr.us-east-1.amazonaws.com",
		Repository: "nested/repo", Hash: "sha256:owner", Tag: "ignored",
	}
	var accounts, tokens []string
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		accounts = append(accounts, aws.ToString(input.RegistryId))
		tokens = append(tokens, aws.ToString(input.NextToken))
		assert.Equal(t, image.Repository, aws.ToString(input.RepositoryName))
		assert.Equal(t, image.Hash, aws.ToString(input.ImageId.ImageDigest))
		assert.Nil(t, input.ImageId.ImageTag)
		out := &ecr.DescribeImageScanFindingsOutput{
			ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{
				{Name: aws.String("CVE-" + aws.ToString(input.NextToken))},
			}},
		}
		switch aws.ToString(input.NextToken) {
		case "":
			out.NextToken = aws.String("second")
		case "second":
			out.NextToken = aws.String("third")
		case "third":
		default:
			t.Fatalf("unexpected continuation %q", aws.ToString(input.NextToken))
		}
		return out, nil
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 3)
	assert.Equal(t, []string{"", "second", "third"}, tokens)
	assert.Equal(t, []string{"222222222222", "222222222222", "222222222222"}, accounts)
}

func TestECRAccountSelection_MixedAccountsRemainSeparate(t *testing.T) {
	images := []ContainerImageIdentifier{
		{Registry: "111111111111.dkr.ecr.us-east-1.amazonaws.com", Repository: "same", Tag: "same"},
		{Registry: "222222222222.dkr.ecr.us-east-1.amazonaws.com", Repository: "same", Tag: "same"},
	}
	for _, operation := range []string{"status", "vulnerabilities"} {
		t.Run(operation, func(t *testing.T) {
			var accounts []string
			a := NewAWSECRAdaptor()
			a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
				account := aws.ToString(input.RegistryId)
				accounts = append(accounts, account)
				status := types.ScanStatusComplete
				if account == "222222222222" {
					status = types.ScanStatusPending
				}
				return &ecr.DescribeImageScanFindingsOutput{
					ImageScanStatus: &types.ImageScanStatus{Status: status},
					ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{
						{Name: aws.String("CVE-" + account)},
					}},
				}, nil
			}}
			if operation == "status" {
				statuses, err := a.GetImagesScanStatus(context.Background(), images)
				require.NoError(t, err)
				require.Len(t, statuses, 2)
				assert.Equal(t, ScanStatusScanned, statuses[0].Status)
				assert.Equal(t, ScanStatusQueued, statuses[1].Status)
				assert.Equal(t, images[1], statuses[1].ImageID)
			} else {
				reports, err := a.GetImagesVulnerabilities(context.Background(), images)
				require.NoError(t, err)
				require.Len(t, reports, 2)
				for i, account := range []string{"111111111111", "222222222222"} {
					require.Len(t, reports[i].Vulnerabilities, 1)
					assert.Equal(t, "CVE-"+account, reports[i].Vulnerabilities[0].ID)
					assert.Equal(t, images[i], reports[i].ImageID)
				}
			}
			assert.Equal(t, []string{"111111111111", "222222222222"}, accounts)
		})
	}
}

func TestECRAccountSelection_InvalidRegistryDoesNotDefaultToCaller(t *testing.T) {
	images := []ContainerImageIdentifier{
		{Registry: "not-an-ecr-registry", Repository: "bad", Tag: "latest"},
		{Registry: "111111111111.dkr.ecr.us-east-1.amazonaws.com", Repository: "good", Tag: "latest"},
	}
	for _, operation := range []string{"status", "vulnerabilities"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			a := NewAWSECRAdaptor()
			a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
				calls++
				assert.Equal(t, "111111111111", aws.ToString(input.RegistryId))
				assert.Equal(t, "good", aws.ToString(input.RepositoryName))
				return &ecr.DescribeImageScanFindingsOutput{
					ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
				}, nil
			}}
			if operation == "status" {
				statuses, err := a.GetImagesScanStatus(context.Background(), images)
				require.ErrorContains(t, err, "invalid private ECR registry")
				require.Len(t, statuses, 2)
				assert.Equal(t, images[0], statuses[0].ImageID)
				assert.False(t, statuses[0].IsScanAvailable)
				assert.True(t, statuses[1].IsScanAvailable)
			} else {
				reports, err := a.GetImagesVulnerabilities(context.Background(), images)
				require.ErrorContains(t, err, "invalid private ECR registry")
				require.Len(t, reports, 2)
				assert.Equal(t, images[0], reports[0].ImageID)
				assert.Empty(t, reports[0].Vulnerabilities)
				assert.Equal(t, ScanStatusScanned, reports[1].Status)
			}
			assert.Equal(t, 1, calls)
		})
	}
}

func TestECRAccountSelection_PermissionFailureKeepsOtherAccounts(t *testing.T) {
	denied := errors.New("cross-account access denied")
	images := []ContainerImageIdentifier{
		{Registry: "222222222222.dkr.ecr.us-east-1.amazonaws.com", Repository: "same", Tag: "same"},
		{Registry: "111111111111.dkr.ecr.us-east-1.amazonaws.com", Repository: "same", Tag: "same"},
	}
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		if aws.ToString(input.RegistryId) == "222222222222" {
			return nil, denied
		}
		return &ecr.DescribeImageScanFindingsOutput{
			ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
			ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{
				{Name: aws.String("CVE-AVAILABLE")},
			}},
		}, nil
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorIs(t, err, denied)
	require.Len(t, reports, 2)
	assert.Equal(t, images[0], reports[0].ImageID)
	assert.Empty(t, reports[0].Vulnerabilities)
	require.Len(t, reports[1].Vulnerabilities, 1)
	assert.Equal(t, "CVE-AVAILABLE", reports[1].Vulnerabilities[0].ID)
	statuses, err := a.GetImagesScanStatus(context.Background(), images)
	require.ErrorIs(t, err, denied)
	require.Len(t, statuses, 2)
	assert.False(t, statuses[0].IsScanAvailable)
	assert.True(t, statuses[1].IsScanAvailable)
}

func TestECRAccountSelection_NoImageVersionDoesNotQueryAccount(t *testing.T) {
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		t.Fatal("an image without a tag or digest must not issue a request")
		return nil, nil
	}}
	images := []ContainerImageIdentifier{{Registry: "unknown", Repository: "repo"}}
	statuses, err := a.GetImagesScanStatus(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.False(t, statuses[0].IsScanAvailable)
	reports, err := a.GetImagesVulnerabilities(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	assert.Empty(t, reports[0].Vulnerabilities)
}

func TestECRAccountSelection_PaginationFailureKeepsOwnerFindings(t *testing.T) {
	pageErr := errors.New("owner registry unavailable on continuation")
	image := ContainerImageIdentifier{
		Registry:   "222222222222.dkr.ecr.us-east-1.amazonaws.com",
		Repository: "repo", Tag: "release",
	}
	var accounts []string
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		accounts = append(accounts, aws.ToString(input.RegistryId))
		if input.NextToken != nil {
			assert.Equal(t, "next-owner-page", aws.ToString(input.NextToken))
			return nil, pageErr
		}
		return &ecr.DescribeImageScanFindingsOutput{
			NextToken:       aws.String("next-owner-page"),
			ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusActive},
			ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{
				{Severity: aws.String("HIGH"), PackageVulnerabilityDetails: &types.PackageVulnerabilityDetails{
					VulnerabilityId: aws.String("CVE-OWNER-PARTIAL"),
				}},
			}},
		}, nil
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.ErrorIs(t, err, pageErr)
	require.Len(t, reports, 1)
	assert.Equal(t, image, reports[0].ImageID)
	assert.Equal(t, ScanStatusScanned, reports[0].Status)
	require.Len(t, reports[0].Vulnerabilities, 1)
	assert.Equal(t, "CVE-OWNER-PARTIAL", reports[0].Vulnerabilities[0].ID)
	assert.Equal(t, "High", reports[0].Vulnerabilities[0].Severity)
	assert.Equal(t, []string{"222222222222", "222222222222"}, accounts)
}

func TestECRAccountSelection_StatusUsesDigestInChinaRegistry(t *testing.T) {
	image := ContainerImageIdentifier{
		Registry:   "000000000001.dkr.ecr.cn-north-1.amazonaws.com.cn",
		Repository: "team/application", Hash: "sha256:immutable", Tag: "mutable",
	}
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		assert.Equal(t, "000000000001", aws.ToString(input.RegistryId))
		assert.Equal(t, image.Repository, aws.ToString(input.RepositoryName))
		require.NotNil(t, input.ImageId)
		assert.Equal(t, image.Hash, aws.ToString(input.ImageId.ImageDigest))
		assert.Nil(t, input.ImageId.ImageTag)
		return &ecr.DescribeImageScanFindingsOutput{
			ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
		}, nil
	}}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, image, statuses[0].ImageID)
	assert.Equal(t, ScanStatusScanned, statuses[0].Status)
}

func TestECRAccountSelection_DualStackScanMethodsAndPagination(t *testing.T) {
	for _, registry := range []string{
		"123456789012.dkr-ecr.us-east-1.on.aws",
		"123456789012.dkr-ecr-fips.us-east-1.on.aws",
	} {
		t.Run(registry, func(t *testing.T) {
			image := ContainerImageIdentifier{Registry: registry, Repository: "repo", Tag: "release"}
			completed := time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)
			calls := 0
			a := NewAWSECRAdaptor()
			a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
				calls++
				assert.Equal(t, "123456789012", aws.ToString(input.RegistryId))
				assert.Equal(t, image.Repository, aws.ToString(input.RepositoryName))
				assert.Equal(t, image.Tag, aws.ToString(input.ImageId.ImageTag))
				out := &ecr.DescribeImageScanFindingsOutput{
					ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
					ImageScanFindings: &types.ImageScanFindings{
						ImageScanCompletedAt: &completed,
						Findings:             []types.ImageScanFinding{{Name: aws.String("CVE-" + aws.ToString(input.NextToken))}},
					},
				}
				if input.MaxResults == nil && input.NextToken == nil {
					out.NextToken = aws.String("second")
				}
				if input.NextToken != nil {
					assert.Equal(t, "second", aws.ToString(input.NextToken))
				}
				return out, nil
			}}
			statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
			require.NoError(t, err)
			require.Len(t, statuses, 1)
			assert.True(t, statuses[0].IsScanAvailable)
			assert.Equal(t, ScanStatusScanned, statuses[0].Status)
			assert.Equal(t, completed, statuses[0].LastScanDate)
			assert.Equal(t, image, statuses[0].ImageID)
			assert.Equal(t, 1, calls)
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.NoError(t, err)
			require.Len(t, reports, 1)
			assert.Equal(t, image, reports[0].ImageID)
			assert.Equal(t, ScanStatusScanned, reports[0].Status)
			require.Len(t, reports[0].Vulnerabilities, 2)
			assert.Equal(t, "CVE-", reports[0].Vulnerabilities[0].ID)
			assert.Equal(t, "CVE-second", reports[0].Vulnerabilities[1].ID)
			assert.Equal(t, 3, calls)
		})
	}
}
