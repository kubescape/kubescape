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
	"github.com/stretchr/testify/require"
)

type mockECRClient struct {
	describeFindingsOut  *ecr.DescribeImageScanFindingsOutput
	describeFindingsErr  error
	describeFindingsFunc func(ctx context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error)
}

func (m *mockECRClient) DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	if params.ImageId != nil && params.ImageId.ImageDigest == nil && params.ImageId.ImageTag == nil {
		panic("InvalidParameterException: imageId must contain either imageDigest or imageTag")
	}
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
		{
			name:    "empty hash and tag should not panic",
			mockOut: &ecr.DescribeImageScanFindingsOutput{
				// the mock client will panic if it reaches DescribeImageScanFindings
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

			if tt.name == "empty hash and tag should not panic" {
				images[0].Tag = ""
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

func TestAWSECRAdaptor_GetImagesVulnerabilities_EmptyHashAndTagShouldNotPanic(t *testing.T) {
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{}

	images := []ContainerImageIdentifier{
		{Registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "test-repo"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Empty(t, reports[0].Vulnerabilities)
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

func TestNextECRVulnerabilityToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		nextToken    *string
		seen         map[string]struct{}
		pagesFetched int
		wantToken    string
		wantNext     bool
		wantError    string
	}{
		{
			name:         "nil token completes pagination",
			nextToken:    nil,
			seen:         map[string]struct{}{},
			pagesFetched: 1,
		},
		{
			name:         "new token advances pagination",
			nextToken:    aws.String("page-two"),
			seen:         map[string]struct{}{},
			pagesFetched: 1,
			wantToken:    "page-two",
			wantNext:     true,
		},
		{ //nolint:gosec // opaque pagination cursor fixture, not a credential
			name:         "opaque token is not normalized",
			nextToken:    aws.String(" token-with-space "),
			seen:         map[string]struct{}{},
			pagesFetched: 1,
			wantToken:    " token-with-space ",
			wantNext:     true,
		},
		{
			name:         "empty token is malformed",
			nextToken:    aws.String(""),
			seen:         map[string]struct{}{},
			pagesFetched: 1,
			wantError:    "empty continuation token",
		},
		{
			name:         "whitespace token is malformed",
			nextToken:    aws.String("  \t "),
			seen:         map[string]struct{}{},
			pagesFetched: 1,
			wantError:    "empty continuation token",
		},
		{
			name:         "immediately repeated token is rejected",
			nextToken:    aws.String("page-two"),
			seen:         map[string]struct{}{"page-two": {}},
			pagesFetched: 2,
			wantError:    `repeated continuation token "page-two"`,
		},
		{
			name:         "cycle to an older token is rejected",
			nextToken:    aws.String("page-two"),
			seen:         map[string]struct{}{"page-two": {}, "page-three": {}},
			pagesFetched: 3,
			wantError:    `repeated continuation token "page-two"`,
		},
		{
			name:         "last allowed page can finish",
			nextToken:    nil,
			seen:         map[string]struct{}{},
			pagesFetched: maxECRVulnerabilityPages,
		},
		{
			name:         "last allowed page cannot continue",
			nextToken:    aws.String("one-page-too-many"),
			seen:         map[string]struct{}{},
			pagesFetched: maxECRVulnerabilityPages,
			wantError:    "exceeded max pages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			before := len(tt.seen)
			token, hasNext, err := nextECRVulnerabilityToken(tt.nextToken, tt.seen, tt.pagesFetched)

			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				assert.Empty(t, token)
				assert.False(t, hasNext)
				assert.Len(t, tt.seen, before, "rejected tokens must not alter cursor state")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, token)
			assert.Equal(t, tt.wantNext, hasNext)
			if tt.wantNext {
				assert.Contains(t, tt.seen, tt.wantToken)
			} else {
				assert.Len(t, tt.seen, before)
			}
		})
	}
}

func TestAWSECRAdaptorPaginationStopsOnImmediateTokenRepeat(t *testing.T) {
	t.Parallel()

	callCount := 0
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(_ context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			callCount++
			if callCount == 1 {
				assert.Nil(t, params.NextToken)
			} else {
				require.NotNil(t, params.NextToken)
				assert.Equal(t, "stalled", aws.ToString(params.NextToken))
			}
			return ecrPage("stalled", fmt.Sprintf("CVE-%d", callCount)), nil
		},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "stalled-repo", Tag: "latest"},
	})

	require.ErrorContains(t, err, `repeated continuation token "stalled"`)
	require.Len(t, reports, 1)
	assert.Equal(t, 2, callCount, "a stalled cursor must be rejected before a third API request")
	assert.Equal(t, []string{"CVE-1", "CVE-2"}, vulnerabilityIDs(reports[0]))
}

func TestAWSECRAdaptorPaginationStopsOnCursorCycle(t *testing.T) {
	t.Parallel()

	responses := []*ecr.DescribeImageScanFindingsOutput{
		ecrPage("cursor-a", "CVE-PAGE-1"),
		ecrPage("cursor-b", "CVE-PAGE-2"),
		ecrPage("cursor-a", "CVE-PAGE-3"),
	}
	requestedTokens := make([]string, 0, len(responses))
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(_ context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			requestedTokens = append(requestedTokens, aws.ToString(params.NextToken))
			return responses[len(requestedTokens)-1], nil
		},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "cyclic-repo", Hash: "sha256:123"},
	})

	require.ErrorContains(t, err, `repeated continuation token "cursor-a"`)
	assert.Equal(t, []string{"", "cursor-a", "cursor-b"}, requestedTokens)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-PAGE-1", "CVE-PAGE-2", "CVE-PAGE-3"}, vulnerabilityIDs(reports[0]))
}

func TestAWSECRAdaptorPaginationRejectsEmptyToken(t *testing.T) {
	t.Parallel()

	callCount := 0
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			callCount++
			return ecrPage("", "CVE-PARTIAL"), nil
		},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "empty-token", Tag: "latest"},
	})

	require.ErrorContains(t, err, "empty continuation token")
	assert.Equal(t, 1, callCount)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-PARTIAL"}, vulnerabilityIDs(reports[0]), "data from the fetched page must remain available with the error")
}

func TestAWSECRAdaptorPaginationKeepsOtherImageResults(t *testing.T) {
	t.Parallel()

	callsByRepository := map[string]int{}
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(_ context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			repository := aws.ToString(params.RepositoryName)
			callsByRepository[repository]++
			switch repository {
			case "healthy":
				return ecrFinalPage("CVE-HEALTHY"), nil
			case "stalled":
				return ecrPage("same-token", fmt.Sprintf("CVE-STALL-%d", callsByRepository[repository])), nil
			default:
				return nil, fmt.Errorf("unexpected repository %s", repository)
			}
		},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "healthy", Tag: "latest"},
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "stalled", Tag: "latest"},
	})

	require.ErrorContains(t, err, "repeated continuation token")
	require.Len(t, reports, 2, "ProcessImages must retain its one-result-per-image contract")
	assert.Equal(t, []string{"CVE-HEALTHY"}, vulnerabilityIDs(reports[0]))
	assert.Equal(t, []string{"CVE-STALL-1", "CVE-STALL-2"}, vulnerabilityIDs(reports[1]))
	assert.Equal(t, map[string]int{"healthy": 1, "stalled": 2}, callsByRepository)
}

func TestAWSECRAdaptorPaginationUsesEveryDistinctTokenOnce(t *testing.T) {
	t.Parallel()

	pages := map[string]*ecr.DescribeImageScanFindingsOutput{
		"":       ecrPage("second", "CVE-FIRST"),
		"second": ecrPage("third", "CVE-SECOND"),
		"third":  ecrFinalPage("CVE-THIRD"),
	}
	requests := make([]string, 0, len(pages))
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(_ context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			token := aws.ToString(params.NextToken)
			requests = append(requests, token)
			page, ok := pages[token]
			if !ok {
				return nil, fmt.Errorf("unexpected token %q", token)
			}
			return page, nil
		},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "healthy", Tag: "latest"},
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"", "second", "third"}, requests)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-FIRST", "CVE-SECOND", "CVE-THIRD"}, vulnerabilityIDs(reports[0]))
}

func TestAWSECRAdaptorPaginationReturnsAPIErrorsWithPartialData(t *testing.T) {
	t.Parallel()

	callCount := 0
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			callCount++
			if callCount == 1 {
				return ecrPage("second", "CVE-FIRST"), nil
			}
			return nil, fmt.Errorf("temporary ECR failure")
		},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "partial", Tag: "latest"},
	})

	require.ErrorContains(t, err, "temporary ECR failure")
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-FIRST"}, vulnerabilityIDs(reports[0]))
	assert.Equal(t, 2, callCount)
}

func TestAWSECRAdaptorPaginationCursorStateIsScopedPerImage(t *testing.T) {
	t.Parallel()

	callsByRepository := map[string]int{}
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(_ context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			repository := aws.ToString(params.RepositoryName)
			callsByRepository[repository]++
			if params.NextToken == nil {
				return ecrPage("shared-token", repository+"-first"), nil
			}
			assert.Equal(t, "shared-token", aws.ToString(params.NextToken))
			return ecrFinalPage(repository + "-second"), nil
		},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "first-repo", Tag: "latest"},
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "second-repo", Tag: "latest"},
	})

	require.NoError(t, err)
	require.Len(t, reports, 2)
	assert.Equal(t, []string{"first-repo-first", "first-repo-second"}, vulnerabilityIDs(reports[0]))
	assert.Equal(t, []string{"second-repo-first", "second-repo-second"}, vulnerabilityIDs(reports[1]))
	assert.Equal(t, map[string]int{"first-repo": 2, "second-repo": 2}, callsByRepository)
}

func TestAWSECRAdaptorPaginationAdvancesAcrossEmptyFindingPages(t *testing.T) {
	t.Parallel()

	requests := []string{}
	adaptor := NewAWSECRAdaptor()
	adaptor.client = &mockECRClient{
		describeFindingsFunc: func(_ context.Context, params *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			token := aws.ToString(params.NextToken)
			requests = append(requests, token)
			switch token {
			case "":
				return &ecr.DescribeImageScanFindingsOutput{NextToken: aws.String("empty-page")}, nil
			case "empty-page":
				return ecrFinalPage("CVE-AFTER-EMPTY-PAGE"), nil
			default:
				return nil, fmt.Errorf("unexpected token %q", token)
			}
		},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{
		{Registry: "12345.dkr.ecr.us-east-1.amazonaws.com", Repository: "sparse", Tag: "latest"},
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"", "empty-page"}, requests)
	require.Len(t, reports, 1)
	assert.Equal(t, []string{"CVE-AFTER-EMPTY-PAGE"}, vulnerabilityIDs(reports[0]))
}

func ecrPage(nextToken, vulnerabilityID string) *ecr.DescribeImageScanFindingsOutput {
	return &ecr.DescribeImageScanFindingsOutput{
		NextToken: aws.String(nextToken),
		ImageScanFindings: &types.ImageScanFindings{
			Findings: []types.ImageScanFinding{{
				Name:        aws.String(vulnerabilityID),
				Severity:    types.FindingSeverityHigh,
				Description: aws.String("fixture vulnerability"),
			}},
		},
	}
}

func ecrFinalPage(vulnerabilityID string) *ecr.DescribeImageScanFindingsOutput {
	page := ecrPage("unused", vulnerabilityID)
	page.NextToken = nil
	return page
}
