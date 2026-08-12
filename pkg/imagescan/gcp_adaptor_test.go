package imagescan

import (
	"context"
	"fmt"
	"testing"
	"time"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockGCPClient struct {
	occurrences []*grafeaspb.Occurrence
	mockErr     error
	lastReq     *grafeaspb.ListOccurrencesRequest
}

func (m *mockGCPClient) ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, opts ...interface{}) GrafeasIterator {
	m.lastReq = req
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

// newFakeContainerAnalysisClient builds a real *containeranalysis.Client
// backed by a non-blocking, unauthenticated local dial target, so tests can
// exercise client lifecycle (in particular Close()) without needing live GCP
// credentials or network access.
func newFakeContainerAnalysisClient(t *testing.T) *containeranalysis.Client {
	t.Helper()
	c, err := containeranalysis.NewClient(context.Background(),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		option.WithEndpoint("localhost:0"),
	)
	require.NoError(t, err)
	return c
}

func TestGCPAdaptor_setOwningClient_ClosesPreviousClient(t *testing.T) {
	adaptor := NewGCPAdaptor()

	first := newFakeContainerAnalysisClient(t)
	adaptor.setOwningClient(first)
	require.Same(t, first, adaptor.owningClient)

	second := newFakeContainerAnalysisClient(t)
	adaptor.setOwningClient(second)
	require.Same(t, second, adaptor.owningClient)

	// setOwningClient must have already closed the first client when it was
	// replaced; closing an already-closed connection returns an error, which
	// proves it wasn't leaked open.
	assert.Error(t, first.Close(), "previous client should already be closed by setOwningClient")

	assert.NoError(t, adaptor.Destroy())
}

func TestGCPAdaptor_Login_CloseFailureStateClearing(t *testing.T) {
	adaptor := NewGCPAdaptor()
	first := newFakeContainerAnalysisClient(t)
	adaptor.setOwningClient(first)

	// Close it manually so the next Close() inside Login() fails.
	_ = first.Close()

	// Login should fail because closing the previous client fails.
	err := adaptor.Login(context.Background(), "location-docker.pkg.dev/project/repository", RegistryCredentials{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to close previous container analysis client")

	// State clearing check: client must be nil, owningClient must be retained
	assert.Nil(t, adaptor.client, "a.client should be cleared before Close()")
	assert.NotNil(t, adaptor.owningClient, "a.owningClient should be retained when close fails")
}

func TestGCPAdaptor_FilterInjectionPrevention(t *testing.T) {
	mockClient := &mockGCPClient{
		occurrences: []*grafeaspb.Occurrence{},
	}
	adaptor := NewGCPAdaptor()
	adaptor.client = mockClient
	adaptor.projectID = "test-project"

	// Create an image ID with a malicious hash containing a double quote
	images := []ContainerImageIdentifier{
		{Registry: "us-docker.pkg.dev", Repository: "proj/repo/img", Hash: "sha256:malicious\"injection"},
	}

	// Test GetImagesScanStatus
	_, err := adaptor.GetImagesScanStatus(context.Background(), images)
	assert.NoError(t, err)
	require.NotNil(t, mockClient.lastReq)

	// The filter should have the double quote escaped
	expectedResourceURL := "https://us-docker.pkg.dev/proj/repo/img@sha256:malicious\\\"injection"
	expectedFilter := fmt.Sprintf("kind=\"DISCOVERY\" AND resourceUrl=\"%s\"", expectedResourceURL)
	assert.Equal(t, expectedFilter, mockClient.lastReq.Filter)

	// Test GetImagesVulnerabilities
	_, err = adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	require.NotNil(t, mockClient.lastReq)

	expectedVulnFilter := fmt.Sprintf("kind=\"VULNERABILITY\" AND resourceUrl=\"%s\"", expectedResourceURL)
	assert.Equal(t, expectedVulnFilter, mockClient.lastReq.Filter)
}
