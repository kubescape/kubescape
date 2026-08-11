package imagescan

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
)

type mockECRClient struct {
	describeFindingsOut  *ecr.DescribeImageScanFindingsOutput
	describeFindingsErr  error
	describeFindingsFunc func(ctx context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error)
}

func (m *mockECRClient) DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	if m.describeFindingsFunc != nil {
		return m.describeFindingsFunc(ctx, params)
	}
	return m.describeFindingsOut, m.describeFindingsErr
}

func TestAWSECRAdaptor_GetImagesScanStatus(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name          string
		mockOut       *ecr.DescribeImageScanFindingsOutput
		mockErr       error
		expectedScan  bool
		expectedError bool
	}{
		{
			name: "scan complete with findings",
			mockOut: &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &types.ImageScanStatus{
					Status: types.ScanStatusComplete,
				},
				ImageScanFindings: &types.ImageScanFindings{
					ImageScanCompletedAt: &now,
				},
			},
			expectedScan: true,
		},
		{
			name: "enhanced continuous scan active with findings",
			mockOut: &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &types.ImageScanStatus{
					Status: types.ScanStatusActive,
				},
				ImageScanFindings: &types.ImageScanFindings{
					ImageScanCompletedAt: &now,
					EnhancedFindings: []types.EnhancedImageScanFinding{
						{
							Severity: aws.String("HIGH"),
						},
					},
				},
			},
			expectedScan: true,
		},
		{
			name: "scan in progress",
			mockOut: &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &types.ImageScanStatus{
					Status: types.ScanStatusInProgress,
				},
			},
			expectedScan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewAWSECRAdaptor()
			adaptor.client = &mockECRClient{
				describeFindingsOut: tt.mockOut,
				describeFindingsErr: tt.mockErr,
			}

			images := []ContainerImageIdentifier{
				{Registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "test-repo", Tag: "latest"},
			}

			statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, statuses, 1)
				assert.Equal(t, tt.expectedScan, statuses[0].IsScanAvailable)
				if tt.expectedScan {
					assert.Equal(t, now, statuses[0].LastScanDate)
				}
			}
		})
	}
}

func TestAWSECRAdaptor_GetImagesVulnerabilities(t *testing.T) {
	mockOut := &ecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &types.ImageScanFindings{
			Findings: []types.ImageScanFinding{
				{
					Name:        aws.String("CVE-2023-1234"),
					Severity:    types.FindingSeverityHigh,
					Description: aws.String("Test vulnerability"),
					Uri:         aws.String("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"),
				},
			},
		},
	}

	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsOut: mockOut,
	}

	images := []ContainerImageIdentifier{
		{Registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "test-repo", Tag: "latest"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 1)

	vuln := reports[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1234", vuln.ID)
	assert.Equal(t, "High", vuln.Severity)
	assert.Equal(t, "Test vulnerability", vuln.Description)
	assert.Equal(t, []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"}, vuln.Links)
}

func TestAWSECRAdaptor_GetImagesVulnerabilities_EnhancedFindings(t *testing.T) {
	mockOut := &ecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &types.ImageScanFindings{
			EnhancedFindings: []types.EnhancedImageScanFinding{
				{
					Description: aws.String("xmlXIncludeAddNode in libxml2 has a use-after-free"),
					Severity:    aws.String("HIGH"),
					PackageVulnerabilityDetails: &types.PackageVulnerabilityDetails{
						VulnerabilityId: aws.String("CVE-2022-49043"),
						ReferenceUrls: []string{
							"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1094238",
							"https://security-tracker.debian.org/tracker/CVE-2022-49043",
						},
						SourceUrl: aws.String("https://security-tracker.debian.org/tracker/CVE-2022-49043"),
					},
				},
			},
		},
	}

	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsOut: mockOut,
	}

	images := []ContainerImageIdentifier{
		{Registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "test-repo", Tag: "latest"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 1)

	vuln := reports[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2022-49043", vuln.ID)
	assert.Equal(t, "High", vuln.Severity)
	assert.Equal(t, "xmlXIncludeAddNode in libxml2 has a use-after-free", vuln.Description)
	assert.Equal(t, []string{
		"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1094238",
		"https://security-tracker.debian.org/tracker/CVE-2022-49043",
	}, vuln.Links)
}

func TestAWSECRAdaptor_GetImagesVulnerabilities_EnhancedFindingsFallsBackToTitle(t *testing.T) {
	mockOut := &ecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &types.ImageScanFindings{
			EnhancedFindings: []types.EnhancedImageScanFinding{
				{
					Title: aws.String("CVE-2026-1234"),
				},
				{
					Title:                       aws.String("CVE-2026-5678"),
					PackageVulnerabilityDetails: &types.PackageVulnerabilityDetails{},
				},
			},
		},
	}

	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{describeFindingsOut: mockOut}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "test-repo", Tag: "latest"},
	})

	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 2)
	assert.Equal(t, "CVE-2026-1234", reports[0].Vulnerabilities[0].ID)
	assert.Equal(t, "CVE-2026-5678", reports[0].Vulnerabilities[1].ID)
}

func TestAWSECRAdaptor_Login_Success(t *testing.T) {
	adaptor := NewAWSECRAdaptor()

	mockConfigProvider := func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{Region: "us-east-1"}, nil
	}
	mockClientFactory := func(cfg aws.Config) ECRAPI {
		return &mockECRClient{}
	}

	adaptor.configProvider = mockConfigProvider
	adaptor.clientFactory = mockClientFactory

	err := adaptor.Login(context.Background(), "12345.dkr.ecr.us-east-1.amazonaws.com", RegistryCredentials{})
	assert.NoError(t, err)
	assert.NotNil(t, adaptor.client)
}

func TestAWSECRAdaptor_Pagination(t *testing.T) {
	adaptor := NewAWSECRAdaptor()

	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(ctx context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			if params.NextToken == nil {
				return &ecr.DescribeImageScanFindingsOutput{
					NextToken: aws.String("token-page-2"),
					ImageScanFindings: &types.ImageScanFindings{
						Findings: []types.ImageScanFinding{
							{
								Name:        aws.String("CVE-PAGE-1"),
								Severity:    types.FindingSeverityHigh,
								Description: aws.String("Page 1 vuln"),
							},
						},
					},
				}, nil
			}
			if *params.NextToken == "token-page-2" {
				return &ecr.DescribeImageScanFindingsOutput{
					NextToken: nil, // End of pages
					ImageScanFindings: &types.ImageScanFindings{
						Findings: []types.ImageScanFinding{
							{
								Name:        aws.String("CVE-PAGE-2"),
								Severity:    types.FindingSeverityLow,
								Description: aws.String("Page 2 vuln"),
							},
						},
					},
				}, nil
			}
			return nil, fmt.Errorf("unexpected token")
		},
	}

	images := []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "test-repo", Tag: "latest"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 2)
	assert.Equal(t, "CVE-PAGE-1", reports[0].Vulnerabilities[0].ID)
	assert.Equal(t, "CVE-PAGE-2", reports[0].Vulnerabilities[1].ID)
}
