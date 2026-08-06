package imagescan

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/stretchr/testify/assert"
)

type mockAzureClient struct {
	resourcesOut armresourcegraph.ClientResourcesResponse
	mockErr      error
}

func (m *mockAzureClient) Resources(ctx context.Context, query armresourcegraph.QueryRequest, options *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	return m.resourcesOut, m.mockErr
}

func TestAzureAdaptor_GetImagesScanStatus(t *testing.T) {
	tests := []struct {
		name          string
		mockOut       armresourcegraph.ClientResourcesResponse
		mockErr       error
		expectedScan  bool
		expectedError bool
	}{
		{
			name: "scan complete",
			mockOut: armresourcegraph.ClientResourcesResponse{
				QueryResponse: armresourcegraph.QueryResponse{
					TotalRecords: to.Ptr[int64](1),
				},
			},
			expectedScan: true,
		},
		{
			name: "scan pending or no data",
			mockOut: armresourcegraph.ClientResourcesResponse{
				QueryResponse: armresourcegraph.QueryResponse{
					TotalRecords: to.Ptr[int64](0),
				},
			},
			expectedScan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewAzureAdaptor()
			adaptor.client = &mockAzureClient{
				resourcesOut: tt.mockOut,
				mockErr:      tt.mockErr,
			}

			images := []ContainerImageIdentifier{
				{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:1234"},
			}

			statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, statuses, 1)
				assert.Equal(t, tt.expectedScan, statuses[0].IsScanAvailable)
				if tt.expectedScan {
					assert.WithinDuration(t, time.Now(), statuses[0].LastScanDate, time.Second)
				}
			}
		})
	}
}

func TestAzureAdaptor_GetImagesVulnerabilities(t *testing.T) {
	mockOut := armresourcegraph.ClientResourcesResponse{
		QueryResponse: armresourcegraph.QueryResponse{
			Data: []interface{}{
				map[string]interface{}{
					"id":          "CVE-2023-1234",
					"severity":    "High",
					"description": "Test vulnerability",
				},
			},
		},
	}

	adaptor := NewAzureAdaptor()
	adaptor.client = &mockAzureClient{
		resourcesOut: mockOut,
	}

	images := []ContainerImageIdentifier{
		{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:1234"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 1)

	vuln := reports[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1234", vuln.ID)
	assert.Equal(t, "High", vuln.Severity)
	assert.Equal(t, "Test vulnerability", vuln.Description)
}
