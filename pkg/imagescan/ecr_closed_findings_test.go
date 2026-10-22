package imagescan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/require"
)

func TestECRClosedFindingIsNotCurrentVulnerability(t *testing.T) {
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsOut: &ecr.DescribeImageScanFindingsOutput{
		ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusActive},
		ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{{
			Status: aws.String("CLOSED"), Severity: aws.String("CRITICAL"),
			PackageVulnerabilityDetails: &types.PackageVulnerabilityDetails{VulnerabilityId: aws.String("CVE-2026-1001")},
		}}},
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{{
		Registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "app", Tag: "latest",
	}})
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
}

func lifecycleFinding(id string, status *string) types.EnhancedImageScanFinding {
	return types.EnhancedImageScanFinding{
		Status:      status,
		Severity:    aws.String("HIGH"),
		Title:       aws.String("Advisory title"),
		Description: aws.String("Detailed advisory description"),
		PackageVulnerabilityDetails: &types.PackageVulnerabilityDetails{
			VulnerabilityId: aws.String(id),
			ReferenceUrls:   []string{"https://example.org/advisory"},
			SourceUrl:       aws.String("https://example.org/source"),
		},
	}
}

func lifecycleImage() ContainerImageIdentifier {
	return ContainerImageIdentifier{
		Registry:   "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		Repository: "team/app", Tag: "release", Hash: "sha256:abc",
	}
}

func lifecycleIDs(reports []ContainerImageVulnerabilityReport) []string {
	var ids []string
	for _, report := range reports {
		for _, v := range report.Vulnerabilities {
			ids = append(ids, v.ID)
		}
	}
	return ids
}

func TestECRClosedOnlyExplicitClosureIsFiltered(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state *string
		keep  bool
	}{
		{"active", aws.String("ACTIVE"), true},
		{"suppressed", aws.String("SUPPRESSED"), true},
		{"closed", aws.String("CLOSED"), false},
		{"lowercase closed", aws.String("closed"), false},
		{"surrounding whitespace", aws.String(" CLOSED "), false},
		{"unknown future state", aws.String("NEW_STATE"), true},
		{"missing state", nil, true},
		{"empty state", aws.String(""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAWSECRAdaptor()
			a.client = &mockECRClient{describeFindingsOut: &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusActive},
				ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{
					lifecycleFinding("CVE-2026-2001", tc.state),
				}},
			}}
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
			require.NoError(t, err)
			require.Len(t, reports, 1)
			require.Equal(t, lifecycleImage(), reports[0].ImageID)
			require.Equal(t, ScanStatusScanned, reports[0].Status)
			if tc.keep {
				require.Equal(t, []string{"CVE-2026-2001"}, lifecycleIDs(reports))
			} else {
				require.Empty(t, reports[0].Vulnerabilities)
			}
		})
	}
}

func TestECRClosedDoesNotRemoveAnotherActiveInstance(t *testing.T) {
	active := lifecycleFinding("CVE-2026-3001", aws.String("ACTIVE"))
	closed := lifecycleFinding("CVE-2026-3001", aws.String("CLOSED"))
	for _, findings := range [][]types.EnhancedImageScanFinding{{closed, active}, {active, closed}} {
		a := NewAWSECRAdaptor()
		a.client = &mockECRClient{describeFindingsOut: &ecr.DescribeImageScanFindingsOutput{
			ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: findings},
		}}
		reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
		require.NoError(t, err)
		require.Equal(t, []string{"CVE-2026-3001"}, lifecycleIDs(reports))
		require.Equal(t, "High", reports[0].Vulnerabilities[0].Severity)
		require.Equal(t, "Detailed advisory description", reports[0].Vulnerabilities[0].Description)
		require.Equal(t, []string{"https://example.org/advisory", "https://example.org/source"}, reports[0].Vulnerabilities[0].Links)
	}
}

func TestECRClosedPageStillFollowsPagination(t *testing.T) {
	for _, firstState := range []string{"CLOSED", "ACTIVE"} {
		t.Run(firstState, func(t *testing.T) {
			calls := 0
			a := NewAWSECRAdaptor()
			a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
				calls++
				require.Equal(t, "123456789012", aws.ToString(input.RegistryId))
				require.Equal(t, "team/app", aws.ToString(input.RepositoryName))
				require.Equal(t, "sha256:abc", aws.ToString(input.ImageId.ImageDigest))
				require.Nil(t, input.ImageId.ImageTag, "digest must retain precedence")
				if input.NextToken == nil {
					return &ecr.DescribeImageScanFindingsOutput{
						ImageScanStatus:   &types.ImageScanStatus{Status: types.ScanStatusActive},
						ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{lifecycleFinding("CVE-first", aws.String(firstState))}},
						NextToken:         aws.String("opaque-next"),
					}, nil
				}
				require.Equal(t, "opaque-next", aws.ToString(input.NextToken))
				return &ecr.DescribeImageScanFindingsOutput{
					ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{
						lifecycleFinding("CVE-active", aws.String("ACTIVE")),
						lifecycleFinding("CVE-closed", aws.String("CLOSED")),
					}},
				}, nil
			}}
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
			require.NoError(t, err)
			require.Equal(t, 2, calls)
			want := []string{"CVE-active"}
			if firstState == "ACTIVE" {
				want = append([]string{"CVE-first"}, want...)
			}
			require.Equal(t, want, lifecycleIDs(reports))
			require.Equal(t, ScanStatusScanned, reports[0].Status)
		})
	}
}

func TestECRClosedPagesPreserveLaterErrors(t *testing.T) {
	for _, firstState := range []string{"CLOSED", "ACTIVE"} {
		t.Run(firstState, func(t *testing.T) {
			failure := errors.New("fixture second page failure")
			a := NewAWSECRAdaptor()
			a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
				if input.NextToken != nil {
					return nil, failure
				}
				return &ecr.DescribeImageScanFindingsOutput{
					ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusActive},
					ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{
						lifecycleFinding("CVE-first", aws.String(firstState)),
					}},
					NextToken: aws.String("next"),
				}, nil
			}}
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
			require.ErrorIs(t, err, failure)
			require.Len(t, reports, 1)
			require.Equal(t, ScanStatusScanned, reports[0].Status)
			if firstState == "ACTIVE" {
				require.Equal(t, []string{"CVE-first"}, lifecycleIDs(reports))
			} else {
				require.Empty(t, reports[0].Vulnerabilities)
			}
		})
	}
}

func TestECRClosedBasicFindingsRemainVisible(t *testing.T) {
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsOut: &ecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &types.ImageScanFindings{
			Findings: []types.ImageScanFinding{{
				Name: aws.String("CVE-basic"), Severity: types.FindingSeverityCritical,
				Description: aws.String("Basic scanner finding"), Uri: aws.String("https://example.org/basic"),
			}},
			EnhancedFindings: []types.EnhancedImageScanFinding{
				lifecycleFinding("CVE-basic", aws.String("CLOSED")),
				lifecycleFinding("CVE-enhanced", aws.String("ACTIVE")),
			},
		},
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
	require.NoError(t, err)
	require.Equal(t, []string{"CVE-basic", "CVE-enhanced"}, lifecycleIDs(reports))
	require.Equal(t, "Critical", reports[0].Vulnerabilities[0].Severity)
	require.Equal(t, []string{"https://example.org/basic"}, reports[0].Vulnerabilities[0].Links)
}

func TestECRClosedMixedBatchKeepsImageOrdering(t *testing.T) {
	images := []ContainerImageIdentifier{lifecycleImage(), lifecycleImage(), lifecycleImage()}
	images[0].Repository = "closed"
	images[1].Repository = "active"
	images[2].Repository = "suppressed"
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		repo := aws.ToString(input.RepositoryName)
		state := "ACTIVE"
		switch repo {
		case "closed":
			state = "CLOSED"
		case "suppressed":
			state = "SUPPRESSED"
		}
		return &ecr.DescribeImageScanFindingsOutput{
			ImageScanStatus:   &types.ImageScanStatus{Status: types.ScanStatusActive},
			ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{lifecycleFinding("CVE-"+repo, aws.String(state))}},
		}, nil
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, reports, 3)
	for i := range images {
		require.Equal(t, images[i], reports[i].ImageID)
		require.Equal(t, ScanStatusScanned, reports[i].Status)
	}
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, []string{"CVE-active", "CVE-suppressed"}, lifecycleIDs(reports))
}

func TestECRClosedFilteringDoesNotMutateSDKResponse(t *testing.T) {
	response := &ecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{
			lifecycleFinding("CVE-closed", aws.String("CLOSED")),
			lifecycleFinding("CVE-active", aws.String("ACTIVE")),
		}},
	}
	before, err := json.Marshal(response)
	require.NoError(t, err)
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsOut: response}
	for i := 0; i < 3; i++ {
		reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
		require.NoError(t, err)
		require.Equal(t, []string{"CVE-active"}, lifecycleIDs(reports))
	}
	after, err := json.Marshal(response)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestECRClosedScanStatusIsIndependentOfFindingState(t *testing.T) {
	completedAt := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsOut: &ecr.DescribeImageScanFindingsOutput{
		ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
		ImageScanFindings: &types.ImageScanFindings{
			ImageScanCompletedAt: &completedAt,
			EnhancedFindings:     []types.EnhancedImageScanFinding{lifecycleFinding("CVE-closed", aws.String("CLOSED"))},
		},
	}}
	statuses, err := a.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.True(t, statuses[0].IsScanAvailable)
	require.Equal(t, completedAt, statuses[0].LastScanDate)
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
	require.NoError(t, err)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
}

func TestECRClosedAllClosedPagesTerminateNormally(t *testing.T) {
	a := NewAWSECRAdaptor()
	calls := 0
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		calls++
		require.LessOrEqual(t, calls, 3)
		out := &ecr.DescribeImageScanFindingsOutput{
			ImageScanStatus:   &types.ImageScanStatus{Status: types.ScanStatusActive},
			ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{lifecycleFinding(fmt.Sprintf("CVE-page-%d", calls), aws.String("CLOSED"))}},
		}
		if calls < 3 {
			out.NextToken = aws.String(fmt.Sprintf("page-%d", calls+1))
		}
		return out, nil
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
	require.NoError(t, err)
	require.Equal(t, 3, calls)
	require.Empty(t, reports[0].Vulnerabilities)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
}

func TestECRClosedReportSerializationRetainsOnlyCurrentFindings(t *testing.T) {
	a := NewAWSECRAdaptor()
	a.client = &mockECRClient{describeFindingsOut: &ecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{
			lifecycleFinding("CVE-remediated", aws.String("CLOSED")),
			lifecycleFinding("CVE-current", aws.String("ACTIVE")),
		}},
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
	require.NoError(t, err)
	data, err := json.Marshal(reports)
	require.NoError(t, err)
	var decoded []ContainerImageVulnerabilityReport
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, []string{"CVE-current"}, lifecycleIDs(decoded))
	require.False(t, slices.Contains(lifecycleIDs(decoded), "CVE-remediated"))
}

func TestECRClosedFilteringThroughRealSDKDecoder(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.Header.Get("X-Amz-Target"), "DescribeImageScanFindings")
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "123456789012", body["registryId"])
		require.Equal(t, "team/app", body["repositoryName"])
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		fmt.Fprint(w, `{
			"imageScanStatus":{"status":"ACTIVE"},
			"imageScanFindings":{"enhancedFindings":[
				{"status":"CLOSED","severity":"CRITICAL","packageVulnerabilityDetails":{"vulnerabilityId":"CVE-fixed"}},
				{"status":"ACTIVE","severity":"HIGH","packageVulnerabilityDetails":{"vulnerabilityId":"CVE-current"}}
			]}
		}`)
	}))
	defer server.Close()
	a := NewAWSECRAdaptor()
	a.client = ecr.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  server.Client(),
	}, func(o *ecr.Options) {
		o.BaseEndpoint = aws.String(server.URL)
	})
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Equal(t, []string{"CVE-current"}, lifecycleIDs(reports))
	require.Equal(t, "High", reports[0].Vulnerabilities[0].Severity)
	require.Equal(t, ScanStatusScanned, reports[0].Status)
}

func TestECRClosedDoesNotPromoteIncompleteScans(t *testing.T) {
	for _, state := range []types.ScanStatus{
		types.ScanStatusInProgress,
		types.ScanStatusFailed,
		types.ScanStatusScanEligibilityExpired,
		types.ScanStatusUnsupportedImage,
	} {
		t.Run(string(state), func(t *testing.T) {
			a := NewAWSECRAdaptor()
			a.client = &mockECRClient{describeFindingsOut: &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &types.ImageScanStatus{Status: state},
				ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{
					lifecycleFinding("CVE-old", aws.String("CLOSED")),
				}},
			}}
			reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
			require.NoError(t, err)
			require.Empty(t, reports[0].Vulnerabilities)
			require.NotEqual(t, ScanStatusScanned, reports[0].Status)
			require.Equal(t, mapECRScanStatus(&types.ImageScanStatus{Status: state}), reports[0].Status)
		})
	}
}

func TestECRClosedPagesDoNotBypassCursorCycleGuard(t *testing.T) {
	a := NewAWSECRAdaptor()
	calls := 0
	a.client = &mockECRClient{describeFindingsFunc: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
		calls++
		return &ecr.DescribeImageScanFindingsOutput{
			ImageScanFindings: &types.ImageScanFindings{EnhancedFindings: []types.EnhancedImageScanFinding{
				lifecycleFinding("CVE-closed", aws.String("CLOSED")),
			}},
			NextToken: aws.String("same"),
		}, nil
	}}
	reports, err := a.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{lifecycleImage()})
	require.ErrorContains(t, err, "repeated continuation token")
	require.Equal(t, 2, calls)
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Vulnerabilities)
}
