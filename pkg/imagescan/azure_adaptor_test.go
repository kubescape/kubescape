package imagescan

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/stretchr/testify/assert"
)

type mockAzureClient struct {
	resourcesOut func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error)
}

func (m *mockAzureClient) Resources(ctx context.Context, query armresourcegraph.QueryRequest, options *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	if m.resourcesOut != nil {
		return m.resourcesOut(query)
	}
	return armresourcegraph.ClientResourcesResponse{}, nil
}

func TestAzureAdaptor_Login_ExplicitCreds(t *testing.T) {
	adaptor := NewAzureAdaptor()
	err := adaptor.Login(context.Background(), "test.azurecr.io", RegistryCredentials{Username: "foo"})
	assert.ErrorContains(t, err, "explicit credentials are intentionally unsupported")
}

func TestAzureAdaptor_resolveAzureCloudConfig(t *testing.T) {
	_, err := resolveAzureCloudConfig("test.docker.io")
	assert.ErrorContains(t, err, "invalid Azure registry format")

	_, err = resolveAzureCloudConfig("test.azurecr.us")
	assert.NoError(t, err)

	_, err = resolveAzureCloudConfig("MyRegistry.azurecr.io")
	assert.NoError(t, err)
}

func TestAzureAdaptor_KQLValidation(t *testing.T) {
	adaptor := NewAzureAdaptor()
	adaptor.registryHost = "test.azurecr.io"

	// Mixed-case validation test
	err := adaptor.validateImageID(ContainerImageIdentifier{Registry: "Test.AzureCR.io", Repository: "repo", Hash: "sha256:123"})
	assert.NoError(t, err)

	err = adaptor.validateImageID(ContainerImageIdentifier{Registry: "wrong.azurecr.io", Repository: "repo", Hash: "sha256:123"})
	assert.ErrorContains(t, err, "does not match logged-in registry")

	// KQL breakout injection test
	err = adaptor.validateImageID(ContainerImageIdentifier{Registry: "test.azurecr.io", Repository: "repo\" or 1=1", Hash: "sha256:123"})
	assert.ErrorContains(t, err, "invalid characters")

	err = adaptor.validateImageID(ContainerImageIdentifier{Registry: "test.azurecr.io", Repository: "repo", Hash: "$()"})
	assert.ErrorContains(t, err, "invalid characters")
}

func TestAzureAdaptor_GetImagesInformation_Guards(t *testing.T) {
	adaptor := NewAzureAdaptor()
	_, err := adaptor.GetImagesInformation(context.Background(), nil)
	assert.ErrorContains(t, err, "azure client not initialized")
}

func TestAzureAdaptor_NormalizeSeverity(t *testing.T) {
	assert.Equal(t, "Critical", normalizeAzureSeverity("Critical"))
	assert.Equal(t, "High", normalizeAzureSeverity("High"))
	assert.Equal(t, "Medium", normalizeAzureSeverity("Medium"))
	assert.Equal(t, "Low", normalizeAzureSeverity("Low"))
	assert.Equal(t, "Negligible", normalizeAzureSeverity("Informational"))
	assert.Equal(t, "Unknown", normalizeAzureSeverity("SomethingElse"))
}

func TestAzureAdaptor_GetImagesScanStatus(t *testing.T) {
	tests := []struct {
		name          string
		mockFunc      func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error)
		expectedScan  bool
		expectedError bool
	}{
		{
			name: "scan complete with timeGenerated",
			mockFunc: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				return armresourcegraph.ClientResourcesResponse{
					QueryResponse: armresourcegraph.QueryResponse{
						TotalRecords: to.Ptr[int64](1),
						Data: []interface{}{
							map[string]interface{}{
								"timeGenerated": "2023-01-01T12:00:00Z",
							},
						},
					},
				}, nil
			},
			expectedScan: true,
		},
		{
			name: "scan pending or no data",
			mockFunc: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				return armresourcegraph.ClientResourcesResponse{
					QueryResponse: armresourcegraph.QueryResponse{
						TotalRecords: to.Ptr[int64](0),
					},
				}, nil
			},
			expectedScan: false,
		},
		{
			name: "arg api error path",
			mockFunc: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
				return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("arg failed")
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptor := NewAzureAdaptor()
			adaptor.registryHost = "test.azurecr.io"
			adaptor.client = &mockAzureClient{resourcesOut: tt.mockFunc}

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
				if tt.name == "scan complete with timeGenerated" {
					expectedTime, _ := time.Parse(time.RFC3339Nano, "2023-01-01T12:00:00Z")
					assert.Equal(t, expectedTime, statuses[0].LastScanDate)
				}
			}
		})
	}
}

func TestAzureAdaptor_GetImagesVulnerabilities_PaginationAndCVE(t *testing.T) {
	callCount := 0

	adaptor := NewAzureAdaptor()
	adaptor.registryHost = "test.azurecr.io"
	adaptor.client = &mockAzureClient{
		resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			callCount++
			if callCount == 1 {
				return armresourcegraph.ClientResourcesResponse{
					QueryResponse: armresourcegraph.QueryResponse{
						Data: []interface{}{
							map[string]interface{}{
								"id":          "vuln1",
								"severity":    "High",
								"description": "Test vuln 1",
								"cve": []interface{}{
									map[string]interface{}{"title": "CVE-2023-1111"},
									map[string]interface{}{"title": "CVE-2023-2222"},
								},
							},
						},
						SkipToken: to.Ptr("token"),
					},
				}, nil
			}
			return armresourcegraph.ClientResourcesResponse{
				QueryResponse: armresourcegraph.QueryResponse{
					Data: []interface{}{
						map[string]interface{}{
							"id":          "vuln2",
							"severity":    "Medium",
							"description": "Test vuln 2",
						},
					},
					SkipToken: nil,
				},
			}, nil
		},
	}

	images := []ContainerImageIdentifier{
		{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:1234"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 3)
	assert.Equal(t, 2, callCount) // Ensure pagination looped exactly twice

	vuln1 := reports[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1111", vuln1.ID) // Primary CVE extracted
	assert.Equal(t, "High", vuln1.Severity)

	vuln2 := reports[0].Vulnerabilities[1]
	assert.Equal(t, "CVE-2023-2222", vuln2.ID) // Second CVE extracted
	assert.Equal(t, "High", vuln2.Severity)

	vuln3 := reports[0].Vulnerabilities[2]
	assert.Equal(t, "vuln2", vuln3.ID) // Fallback to ID
}

func TestAzureAdaptor_GetImagesVulnerabilities_Cap(t *testing.T) {
	// Test that >1000 items truncates instead of failing hard
	adaptor := NewAzureAdaptor()
	adaptor.registryHost = "test.azurecr.io"
	adaptor.client = &mockAzureClient{
		resourcesOut: func(req armresourcegraph.QueryRequest) (armresourcegraph.ClientResourcesResponse, error) {
			data := make([]interface{}, 1005)
			for i := 0; i < 1005; i++ {
				data[i] = map[string]interface{}{"id": fmt.Sprintf("vuln%d", i)}
			}
			return armresourcegraph.ClientResourcesResponse{
				QueryResponse: armresourcegraph.QueryResponse{Data: data},
			}, nil
		},
	}

	images := []ContainerImageIdentifier{
		{Registry: "test.azurecr.io", Repository: "test-repo", Hash: "sha256:1234"},
	}

	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	assert.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Len(t, reports[0].Vulnerabilities, 1000) // Truncated cleanly
}
