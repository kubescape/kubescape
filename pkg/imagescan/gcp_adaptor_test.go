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
	occurrences  []*grafeaspb.Occurrence
	mockErr      error
	errorAfter   int
	lastReq      *grafeaspb.ListOccurrencesRequest
	lastIterator *mockGrafeasIterator
}

func (m *mockGCPClient) ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, opts ...interface{}) GrafeasIterator {
	m.lastReq = req
	it := &mockGrafeasIterator{
		occurrences: m.occurrences,
		err:         m.mockErr,
		errorAfter:  m.errorAfter,
		index:       0,
	}
	m.lastIterator = it
	return it
}

type mockGrafeasIterator struct {
	occurrences []*grafeaspb.Occurrence
	err         error
	errorAfter  int
	index       int
}

func (m *mockGrafeasIterator) Next() (*grafeaspb.Occurrence, error) {
	if m.err != nil && (m.errorAfter == 0 || m.index >= m.errorAfter) {
		return nil, m.err
	}
	if m.index >= len(m.occurrences) {
		return nil, iterator.Done
	}
	occ := m.occurrences[m.index]
	m.index++
	return occ, nil
}

func discoveryOccurrence(scanStatus grafeaspb.DiscoveryOccurrence_AnalysisStatus, updatedAt time.Time) *grafeaspb.Occurrence {
	occurrence := &grafeaspb.Occurrence{
		Details: &grafeaspb.Occurrence_Discovery{
			Discovery: &grafeaspb.DiscoveryOccurrence{AnalysisStatus: scanStatus},
		},
	}
	if !updatedAt.IsZero() {
		occurrence.UpdateTime = timestamppb.New(updatedAt)
	}
	return occurrence
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

// TestGCPAdaptor_GetImagesScanStatus_Bounded guards against an unbounded
// ListOccurrences loop: a registry that keeps returning non-terminal (e.g.
// PENDING) discovery occurrences must not make GetImagesScanStatus walk the
// entire response. Mirrors the maxVulns cap GetImagesVulnerabilities already
// enforces in this file.
func TestGCPAdaptor_GetImagesScanStatus_Bounded(t *testing.T) {
	mockOccurrences := make([]*grafeaspb.Occurrence, 0, 5000)
	for i := 0; i < 5000; i++ {
		mockOccurrences = append(mockOccurrences, &grafeaspb.Occurrence{
			Details: &grafeaspb.Occurrence_Discovery{
				Discovery: &grafeaspb.DiscoveryOccurrence{
					AnalysisStatus: grafeaspb.DiscoveryOccurrence_PENDING, // never terminal
				},
			},
		})
	}

	client := &mockGCPClient{occurrences: mockOccurrences}
	adaptor := NewGCPAdaptor()
	adaptor.client = client

	images := []ContainerImageIdentifier{
		{Registry: "us-docker.pkg.dev", Repository: "my-project/my-repo/my-image", Hash: "sha256:1234"},
	}

	statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.False(t, statuses[0].IsScanAvailable)

	// The mock only reports iterator.Done once every occurrence is consumed,
	// so an index short of len(mockOccurrences) proves the loop stopped on
	// its own cap rather than draining the whole (simulated) response.
	require.NotNil(t, client.lastIterator)
	assert.Less(t, client.lastIterator.index, len(mockOccurrences), "GetImagesScanStatus consumed the entire unbounded response instead of stopping at a cap")
}

func TestMergeSuccessfulGCPScan(t *testing.T) {
	oldScan := time.Date(2023, time.March, 2, 10, 0, 0, 0, time.UTC)
	newScan := time.Date(2025, time.July, 4, 12, 30, 0, 0, time.UTC)

	tests := []struct {
		name          string
		initial       ContainerImageScanStatus
		occurrence    *grafeaspb.Occurrence
		wantAvailable bool
		wantTime      time.Time
	}{
		{
			name:          "nil occurrence",
			occurrence:    nil,
			wantAvailable: false,
		},
		{
			name:          "pending occurrence",
			occurrence:    discoveryOccurrence(grafeaspb.DiscoveryOccurrence_PENDING, newScan),
			wantAvailable: false,
		},
		{
			name: "non discovery occurrence",
			occurrence: &grafeaspb.Occurrence{
				Details: &grafeaspb.Occurrence_Vulnerability{
					Vulnerability: &grafeaspb.VulnerabilityOccurrence{},
				},
			},
			wantAvailable: false,
		},
		{
			name:          "successful occurrence without timestamp",
			occurrence:    discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, time.Time{}),
			wantAvailable: true,
		},
		{
			name:          "successful occurrence sets timestamp",
			occurrence:    discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, newScan),
			wantAvailable: true,
			wantTime:      newScan,
		},
		{
			name: "older success cannot move timestamp backwards",
			initial: ContainerImageScanStatus{
				IsScanAvailable: true,
				LastScanDate:    newScan,
			},
			occurrence:    discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, oldScan),
			wantAvailable: true,
			wantTime:      newScan,
		},
		{
			name: "newer success replaces prior timestamp",
			initial: ContainerImageScanStatus{
				IsScanAvailable: true,
				LastScanDate:    oldScan,
			},
			occurrence:    discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, newScan),
			wantAvailable: true,
			wantTime:      newScan,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.initial
			mergeSuccessfulGCPScan(&status, tt.occurrence)
			assert.Equal(t, tt.wantAvailable, status.IsScanAvailable)
			assert.Equal(t, tt.wantTime, status.LastScanDate)
		})
	}
}

func TestGCPAdaptor_GetImagesScanStatusChoosesNewestSuccessfulOccurrence(t *testing.T) {
	oldScan := time.Date(2022, time.January, 1, 9, 0, 0, 0, time.UTC)
	newScan := time.Date(2025, time.August, 9, 15, 30, 0, 0, time.UTC)
	client := &mockGCPClient{occurrences: []*grafeaspb.Occurrence{
		discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, oldScan),
		discoveryOccurrence(grafeaspb.DiscoveryOccurrence_PENDING, time.Time{}),
		discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, newScan),
	}}
	adaptor := NewGCPAdaptor()
	adaptor.client = client

	statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{{
		Registry:   "us-docker.pkg.dev",
		Repository: "my-project/my-repo/my-image",
		Hash:       "sha256:1234",
	}})

	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.True(t, statuses[0].IsScanAvailable)
	assert.Equal(t, newScan, statuses[0].LastScanDate)
	require.NotNil(t, client.lastIterator)
	assert.Equal(t, 3, client.lastIterator.index, "all returned occurrences must be considered")
}

func TestGCPAdaptor_GetImagesScanStatusDoesNotHideLaterIteratorError(t *testing.T) {
	completedAt := time.Date(2025, time.August, 9, 15, 30, 0, 0, time.UTC)
	client := &mockGCPClient{
		occurrences: []*grafeaspb.Occurrence{
			discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, completedAt),
		},
		mockErr:    fmt.Errorf("provider page failed"),
		errorAfter: 1,
	}
	adaptor := NewGCPAdaptor()
	adaptor.client = client

	statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{{
		Registry:   "us-docker.pkg.dev",
		Repository: "my-project/my-repo/my-image",
		Hash:       "sha256:1234",
	}})

	require.Error(t, err)
	assert.ErrorContains(t, err, "provider page failed")
	require.Len(t, statuses, 1)
	assert.True(t, statuses[0].IsScanAvailable, "the partial status should be retained alongside the error")
	assert.Equal(t, completedAt, statuses[0].LastScanDate)
}

func TestGCPAdaptor_GetImagesScanStatusIgnoresInvalidSuccessfulTimestamp(t *testing.T) {
	invalidTime := &timestamppb.Timestamp{Seconds: 253402300800}
	validTime := time.Date(2024, time.November, 5, 6, 7, 8, 0, time.UTC)
	client := &mockGCPClient{occurrences: []*grafeaspb.Occurrence{
		{
			UpdateTime: invalidTime,
			Details: &grafeaspb.Occurrence_Discovery{
				Discovery: &grafeaspb.DiscoveryOccurrence{
					AnalysisStatus: grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS,
				},
			},
		},
		discoveryOccurrence(grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS, validTime),
	}}
	adaptor := NewGCPAdaptor()
	adaptor.client = client

	statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{{
		Registry:   "us-docker.pkg.dev",
		Repository: "my-project/my-repo/my-image",
		Hash:       "sha256:1234",
	}})

	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.True(t, statuses[0].IsScanAvailable)
	assert.Equal(t, validTime, statuses[0].LastScanDate)
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

	tests := []struct {
		name         string
		hash         string
		expectedHash string
	}{
		{
			name:         "quote only",
			hash:         "sha256:malicious\"injection",
			expectedHash: "sha256:malicious\\\"injection",
		},
		{
			name:         "backslash before quote",
			hash:         "sha256:malicious\\\"injection",
			expectedHash: "sha256:malicious\\\\\\\"injection",
		},
		{
			name:         "trailing backslash",
			hash:         "sha256:malicious\\",
			expectedHash: "sha256:malicious\\\\",
		},
		{
			name:         "raw line break",
			hash:         "sha256:malicious\ninjection",
			expectedHash: "sha256:malicious\\ninjection",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			images := []ContainerImageIdentifier{
				{Registry: "us-docker.pkg.dev", Repository: "proj/repo/img", Hash: tc.hash},
			}

			// Test GetImagesScanStatus
			_, err := adaptor.GetImagesScanStatus(context.Background(), images)
			assert.NoError(t, err)
			require.NotNil(t, mockClient.lastReq)

			expectedResourceURL := "https://us-docker.pkg.dev/proj/repo/img@" + tc.expectedHash
			expectedFilter := fmt.Sprintf("kind=\"DISCOVERY\" AND resourceUrl=\"%s\"", expectedResourceURL)
			assert.Equal(t, expectedFilter, mockClient.lastReq.Filter)

			// Test GetImagesVulnerabilities
			_, err = adaptor.GetImagesVulnerabilities(context.Background(), images)
			assert.NoError(t, err)
			require.NotNil(t, mockClient.lastReq)

			expectedVulnFilter := fmt.Sprintf("kind=\"VULNERABILITY\" AND resourceUrl=\"%s\"", expectedResourceURL)
			assert.Equal(t, expectedVulnFilter, mockClient.lastReq.Filter)
		})
	}
}
