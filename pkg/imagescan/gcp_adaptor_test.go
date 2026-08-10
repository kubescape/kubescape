package imagescan

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockGCPClient struct {
	occurrences []*grafeaspb.Occurrence
	mockErr     error
}

func (m *mockGCPClient) ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, opts ...interface{}) GrafeasIterator {
	return &mockGrafeasIterator{
		occurrences: m.occurrences,
		err:         m.mockErr,
		index:       0,
	}
}

type mockGrafeasIterator struct {
	occurrences []*grafeaspb.Occurrence
	err         error
	index       int
}

func (m *mockGrafeasIterator) Next() (*grafeaspb.Occurrence, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.index >= len(m.occurrences) {
		return nil, iterator.Done
	}
	occ := m.occurrences[m.index]
	m.index++
	return occ, nil
}

func TestGCPAdaptor_GetImagesScanStatus(t *testing.T) {
	now := time.Now()
	nowPb := timestamppb.New(now)

	tests := []struct {
		name          string
		occurrences   []*grafeaspb.Occurrence
		mockErr       error
		expectedScan  bool
		expectedError bool
	}{
		{
			name: "scan complete",
			occurrences: []*grafeaspb.Occurrence{
				{
					UpdateTime: nowPb,
					Details: &grafeaspb.Occurrence_Discovery{
						Discovery: &grafeaspb.DiscoveryOccurrence{
							AnalysisStatus: grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS,
						},
					},
				},
			},
			expectedScan: true,
		},
		{
			name: "scan pending",
			occurrences: []*grafeaspb.Occurrence{
				{
					Details: &grafeaspb.Occurrence_Discovery{
						Discovery: &grafeaspb.DiscoveryOccurrence{
							AnalysisStatus: grafeaspb.DiscoveryOccurrence_PENDING,
						},
					},
				},
			},
			expectedScan: false,
		},
		{
			name:          "api error path aggregates failure",
			mockErr:       fmt.Errorf("simulated API error"),
			expectedError: true,
			expectedScan:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewGCPAdaptor()
			adaptor.client = &mockGCPClient{
				occurrences: tt.occurrences,
				mockErr:     tt.mockErr,
			}

			images := []ContainerImageIdentifier{
				{Registry: "us-docker.pkg.dev", Repository: "my-project/my-repo/my-image", Hash: "sha256:1234"},
			}

			statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, statuses, 1)
				assert.Equal(t, tt.expectedScan, statuses[0].IsScanAvailable)
				if tt.expectedScan {
					// Compare roughly (protobuf truncates precision)
					assert.WithinDuration(t, now, statuses[0].LastScanDate, time.Second)
				}
			}
		})
	}
}

func TestGCPAdaptor_GetImagesVulnerabilities(t *testing.T) {
	mockOccurrences := []*grafeaspb.Occurrence{
		{
			Details: &grafeaspb.Occurrence_Vulnerability{
				Vulnerability: &grafeaspb.VulnerabilityOccurrence{
					ShortDescription:  "CVE-2023-1234",
					EffectiveSeverity: grafeaspb.Severity_HIGH,
					LongDescription:   "Test vulnerability",
					RelatedUrls: []*grafeaspb.RelatedUrl{
						{Url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"},
					},
				},
			},
		},
	}

	adaptor := NewGCPAdaptor()
	adaptor.client = &mockGCPClient{
		occurrences: mockOccurrences,
	}

	images := []ContainerImageIdentifier{
		{Registry: "us-docker.pkg.dev", Repository: "my-project/my-repo/my-image", Hash: "sha256:1234"},
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

func TestGCPAdaptor_GetImagesVulnerabilities_Cap(t *testing.T) {
	mockOccurrences := make([]*grafeaspb.Occurrence, 0, 1005)
	for i := 0; i < 1005; i++ {
		mockOccurrences = append(mockOccurrences, &grafeaspb.Occurrence{
			Details: &grafeaspb.Occurrence_Vulnerability{
				Vulnerability: &grafeaspb.VulnerabilityOccurrence{
					ShortDescription:  fmt.Sprintf("CVE-2023-%d", i),
					EffectiveSeverity: grafeaspb.Severity_LOW,
					LongDescription:   "Test vulnerability",
				},
			},
		})
	}

	adaptor := NewGCPAdaptor()
	adaptor.client = &mockGCPClient{
		occurrences: mockOccurrences,
	}

	images := []ContainerImageIdentifier{
		{Registry: "us-docker.pkg.dev", Repository: "my-project/my-repo/my-image", Hash: "sha256:1234"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 1000) // Should truncate at 1000 without returning an error
}
