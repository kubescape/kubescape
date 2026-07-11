package imagescan

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
)

type mockECRClient struct {
	describeFindingsOut *ecr.DescribeImageScanFindingsOutput
	describeFindingsErr error

	batchGetImageOut *ecr.BatchGetImageOutput
	batchGetImageErr error
}

func (m *mockECRClient) DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	return m.describeFindingsOut, m.describeFindingsErr
}

func (m *mockECRClient) BatchGetImage(ctx context.Context, params *ecr.BatchGetImageInput, optFns ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error) {
	return m.batchGetImageOut, m.batchGetImageErr
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
	assert.Equal(t, string(types.FindingSeverityHigh), vuln.Severity)
	assert.Equal(t, "Test vulnerability", vuln.Description)
	assert.Equal(t, []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"}, vuln.Links)
}

func TestAWSECRAdaptor_GetImagesInformation(t *testing.T) {
	mockOut := &ecr.BatchGetImageOutput{
		Images: []types.Image{
			{
				ImageManifest: aws.String(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`),
			},
		},
	}

	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		batchGetImageOut: mockOut,
	}

	images := []ContainerImageIdentifier{
		{Registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "test-repo", Tag: "latest"},
	}

	infos, err := adaptor.GetImagesInformation(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, infos, 1)
	assert.Empty(t, infos[0].Bom) // BOM should be empty for ECR
}
