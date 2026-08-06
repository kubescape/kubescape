package imagescan

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

var _ IContainerImageVulnerabilityAdaptor = (*AzureAdaptor)(nil)

var validKQLInputRegex = regexp.MustCompile(`^[a-zA-Z0-9.\-_/:]+$`)

// AzureAPI defines the interface for the Azure Resource Graph functions we use, enabling mocking in tests.
type AzureAPI interface {
	Resources(ctx context.Context, query armresourcegraph.QueryRequest, options *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)
}

// azureAPIWrapper implements AzureAPI by wrapping the real armresourcegraph.Client
type azureAPIWrapper struct {
	client *armresourcegraph.Client
}

func (a *azureAPIWrapper) Resources(ctx context.Context, query armresourcegraph.QueryRequest, options *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	return a.client.Resources(ctx, query, options)
}

// AzureAdaptor implements IContainerImageVulnerabilityAdaptor for Azure Container Registry (ACR).
type AzureAdaptor struct {
	client       AzureAPI
	registryName string
}

// NewAzureAdaptor creates a new Azure adaptor instance.
func NewAzureAdaptor() *AzureAdaptor {
	return &AzureAdaptor{}
}

// Login authenticates with Azure. It prioritizes DefaultAzureCredential.
// Explicit credentials passed via RegistryCredentials are intentionally unsupported
// as Azure SDK relies heavily on Managed Identities and Azure CLI credentials.
func (a *AzureAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	if credentials.Username != "" || credentials.Password != "" {
		return fmt.Errorf("explicit credentials are intentionally unsupported for Azure; use DefaultAzureCredential")
	}

	// Extract registry name from registry URL (e.g., myregistry.azurecr.io)
	parts := strings.Split(registry, ".")
	if len(parts) >= 3 && parts[1] == "azurecr" && parts[2] == "io" {
		a.registryName = parts[0]
	} else {
		return fmt.Errorf("invalid Azure registry format: expected registryname.azurecr.io, got %s", registry)
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("unable to load Azure credentials: %w", err)
	}

	c, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return fmt.Errorf("unable to load Azure Resource Graph client: %w", err)
	}

	a.client = &azureAPIWrapper{client: c}
	return nil
}

// DescribeAdaptor provides a string description of the adaptor for help purposes.
func (a *AzureAdaptor) DescribeAdaptor() string {
	return "Azure Container Registry (ACR) Vulnerability Adaptor"
}

// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
func (a *AzureAdaptor) GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error) {
	if a.client == nil {
		return nil, fmt.Errorf("Azure client not initialized, call Login first")
	}

	var statuses []ContainerImageScanStatus

	for _, imageID := range imageIDs {
		status := ContainerImageScanStatus{
			ImageID:         imageID,
			IsScanAvailable: false,
			IsBomAvailable:  false,
		}

		if imageID.Hash == "" {
			statuses = append(statuses, status)
			continue
		}

		if !validKQLInputRegex.MatchString(imageID.Registry) || !validKQLInputRegex.MatchString(imageID.Repository) || !validKQLInputRegex.MatchString(imageID.Hash) {
			return nil, fmt.Errorf("invalid characters in image identifier for KQL query")
		}

		// Query ARG for Microsoft Defender for Cloud assessments (SubAssessment) for the specific image digest
		queryStr := fmt.Sprintf(`
			securityresources
			| where type == "microsoft.security/assessments/subassessments"
			| where properties.additionalData.registryHost == "%s"
			| where properties.additionalData.repositoryName == "%s"
			| where properties.additionalData.imageDigest == "%s"
			| limit 1
		`, imageID.Registry, imageID.Repository, imageID.Hash)

		req := armresourcegraph.QueryRequest{
			Query: to.Ptr(queryStr),
		}

		res, err := a.client.Resources(ctx, req, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to query scan status for repository %s: %w", imageID.Repository, err)
		}

		if res.TotalRecords != nil && *res.TotalRecords > 0 {
			status.IsScanAvailable = true
			status.LastScanDate = time.Now() // Microsoft Defender does not always expose exact completion time in ARG
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// Helper to normalize Azure severity to Kubescape expected severity
func normalizeAzureSeverity(azureSeverity string) string {
	switch strings.ToLower(azureSeverity) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "unassigned", "informational":
		return "Negligible"
	default:
		return "Unknown"
	}
}

// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
func (a *AzureAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	if a.client == nil {
		return nil, fmt.Errorf("Azure client not initialized, call Login first")
	}

	var reports []ContainerImageVulnerabilityReport

	for _, imageID := range imageIDs {
		report := ContainerImageVulnerabilityReport{
			ImageID:         imageID,
			Vulnerabilities: []Vulnerability{},
		}

		if imageID.Hash == "" {
			reports = append(reports, report)
			continue
		}

		if !validKQLInputRegex.MatchString(imageID.Registry) || !validKQLInputRegex.MatchString(imageID.Repository) || !validKQLInputRegex.MatchString(imageID.Hash) {
			return nil, fmt.Errorf("invalid characters in image identifier for KQL query")
		}

		queryStr := fmt.Sprintf(`
			securityresources
			| where type == "microsoft.security/assessments/subassessments"
			| where properties.additionalData.registryHost == "%s"
			| where properties.additionalData.repositoryName == "%s"
			| where properties.additionalData.imageDigest == "%s"
			| project 
				id = properties.id, 
				severity = properties.status.severity,
				description = properties.description,
				remediation = properties.remediation,
				cve = properties.additionalData.cve
		`, imageID.Registry, imageID.Repository, imageID.Hash)

		var skipToken *string
		count := 0
		const maxVulns = 1000

		for {
			req := armresourcegraph.QueryRequest{
				Query: to.Ptr(queryStr),
				Options: &armresourcegraph.QueryRequestOptions{
					SkipToken: skipToken,
					Top:       to.Ptr[int32](1000),
				},
			}

			res, err := a.client.Resources(ctx, req, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to query vulnerabilities for repository %s: %w", imageID.Repository, err)
			}

			if res.Data != nil {
				dataList, ok := res.Data.([]interface{})
				if ok {
					for _, item := range dataList {
						if count >= maxVulns {
							return nil, fmt.Errorf("exceeded max vulnerabilities (%d) fetching vulnerabilities for image %s", maxVulns, imageID.Repository)
						}

						row, ok := item.(map[string]interface{})
						if !ok {
							continue
						}

						vuln := Vulnerability{
							ID:          getStringSafe(row, "id"),
							Severity:    normalizeAzureSeverity(getStringSafe(row, "severity")),
							Description: getStringSafe(row, "description"),
							Links:       []string{}, // ARG doesn't consistently return direct URLs in standard schemas
						}

						if cve := getNestedStringSafe(row, "cve", "title"); cve != "" {
							vuln.ID = cve
						}

						report.Vulnerabilities = append(report.Vulnerabilities, vuln)
						count++
					}
				}
			}

			if res.SkipToken == nil || *res.SkipToken == "" {
				break
			}
			skipToken = res.SkipToken
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
func (a *AzureAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	if a.client == nil {
		return nil, fmt.Errorf("Azure client not initialized, call Login first")
	}

	var infos []ContainerImageInformation

	for _, imageID := range imageIDs {
		info := ContainerImageInformation{
			ImageID: imageID,
			Bom:     []string{},
		}
		infos = append(infos, info)
	}

	return infos, nil
}

func getStringSafe(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getNestedStringSafe(m map[string]interface{}, key1, key2 string) string {
	if val1, ok := m[key1]; ok {
		if nested, ok := val1.([]interface{}); ok && len(nested) > 0 {
			if first, ok := nested[0].(map[string]interface{}); ok {
				return getStringSafe(first, key2)
			}
		}
	}
	return ""
}
