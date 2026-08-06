package imagescan

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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
	registryHost string
}

// NewAzureAdaptor creates a new Azure adaptor instance.
func NewAzureAdaptor() *AzureAdaptor {
	return &AzureAdaptor{}
}

func resolveAzureCloudConfig(registryHost string) (cloud.Configuration, error) {
	registryLower := strings.ToLower(registryHost)
	if strings.HasSuffix(registryLower, ".azurecr.io") {
		return cloud.AzurePublic, nil
	} else if strings.HasSuffix(registryLower, ".azurecr.cn") {
		return cloud.AzureChina, nil
	} else if strings.HasSuffix(registryLower, ".azurecr.us") {
		return cloud.AzureGovernment, nil
	}
	return cloud.Configuration{}, fmt.Errorf("invalid Azure registry format or unsupported cloud: %s", registryHost)
}

// Login authenticates with Azure. It prioritizes DefaultAzureCredential.
// Explicit credentials passed via RegistryCredentials are intentionally unsupported
// as Azure SDK relies heavily on Managed Identities and Azure CLI credentials.
func (a *AzureAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	if credentials.Username != "" || credentials.Password != "" {
		return fmt.Errorf("explicit credentials are intentionally unsupported for Azure; use DefaultAzureCredential")
	}

	cloudConfig, err := resolveAzureCloudConfig(registry)
	if err != nil {
		return err
	}
	a.registryHost = strings.ToLower(registry)

	clientOpts := azcore.ClientOptions{Cloud: cloudConfig}

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: clientOpts,
	})
	if err != nil {
		return fmt.Errorf("unable to load azure credentials: %w", err)
	}

	c, err := armresourcegraph.NewClient(cred, &arm.ClientOptions{
		ClientOptions: clientOpts,
	})
	if err != nil {
		return fmt.Errorf("unable to load azure resource graph client: %w", err)
	}
	a.client = &azureAPIWrapper{client: c}

	// Cheap probe query so Login fails fast on bad/missing identity
	probeReq := armresourcegraph.QueryRequest{
		Query: to.Ptr("securityresources | limit 1"),
	}
	if _, err := a.client.Resources(ctx, probeReq, nil); err != nil {
		return fmt.Errorf("failed azure identity probe: %w", err)
	}

	return nil
}

// DescribeAdaptor provides a string description of the adaptor for help purposes.
func (a *AzureAdaptor) DescribeAdaptor() string {
	return "Azure Container Registry (ACR) Vulnerability Adaptor"
}

func (a *AzureAdaptor) validateImageID(imageID ContainerImageIdentifier) error {
	if !strings.EqualFold(imageID.Registry, a.registryHost) {
		return fmt.Errorf("image registry %s does not match logged-in registry %s", imageID.Registry, a.registryHost)
	}
	if !validKQLInputRegex.MatchString(imageID.Registry) || !validKQLInputRegex.MatchString(imageID.Repository) || !validKQLInputRegex.MatchString(imageID.Hash) {
		return fmt.Errorf("invalid characters in image identifier for KQL query")
	}
	return nil
}

// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
func (a *AzureAdaptor) GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error) {
	if a.client == nil {
		return nil, fmt.Errorf("azure client not initialized, call Login first")
	}

	var statuses []ContainerImageScanStatus
	parts := strings.Split(a.registryHost, ".")
	registryName := parts[0]

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

		if err := a.validateImageID(imageID); err != nil {
			logger.L().Warning("skipping image", helpers.String("repository", imageID.Repository), helpers.Error(err))
			statuses = append(statuses, status)
			continue
		}

		// Query ARG for parent assessment to determine scan availability
		queryStr := fmt.Sprintf(`
			securityresources
			| where type == "microsoft.security/assessments"
			| extend registryName = extract(@"(?i)/registries/([^/]+)/", 1, id)
			| where registryName =~ "%s"
			| where properties.resourceDetails.id contains "%s"
			| project timeGenerated = properties.timeGenerated
			| limit 1
		`, registryName, imageID.Hash)

		req := armresourcegraph.QueryRequest{
			Query: to.Ptr(queryStr),
			Options: &armresourcegraph.QueryRequestOptions{
				ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
			},
		}

		res, err := a.client.Resources(ctx, req, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to query scan status for repository %s: %w", imageID.Repository, err)
		}

		if res.TotalRecords != nil && *res.TotalRecords > 0 {
			status.IsScanAvailable = true
			if res.Data != nil {
				if dataList, ok := res.Data.([]interface{}); ok && len(dataList) > 0 {
					if row, ok := dataList[0].(map[string]interface{}); ok {
						if tg := getStringSafe(row, "timeGenerated"); tg != "" {
							if parsedTime, err := time.Parse(time.RFC3339Nano, tg); err == nil {
								status.LastScanDate = parsedTime
							}
						}
					}
				}
			}
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
		return nil, fmt.Errorf("azure client not initialized, call Login first")
	}

	var reports []ContainerImageVulnerabilityReport
	parts := strings.Split(a.registryHost, ".")
	registryName := parts[0]

	for _, imageID := range imageIDs {
		report := ContainerImageVulnerabilityReport{
			ImageID:         imageID,
			Vulnerabilities: []Vulnerability{},
		}

		if imageID.Hash == "" {
			reports = append(reports, report)
			continue
		}

		if err := a.validateImageID(imageID); err != nil {
			logger.L().Warning("skipping image", helpers.String("repository", imageID.Repository), helpers.Error(err))
			reports = append(reports, report)
			continue
		}

		queryStr := fmt.Sprintf(`
			securityresources
			| where type == "microsoft.security/assessments/subassessments"
			| extend registryName = extract(@"(?i)/registries/([^/]+)/", 1, id)
			| where registryName =~ "%s"
			| where properties.additionalData.assessedResourceType == "ContainerRegistryVulnerability"
			| where properties.additionalData.repositoryName == "%s"
			| where properties.additionalData.imageDigest == "%s"
			| project 
				id = properties.id, 
				severity = properties.status.severity,
				description = properties.description,
				cve = properties.additionalData.cve
		`, registryName, imageID.Repository, imageID.Hash)

		var skipToken *string
		count := 0
		const maxVulns = 1000
		const maxPages = 50

		for page := 0; page < maxPages; page++ {
			req := armresourcegraph.QueryRequest{
				Query: to.Ptr(queryStr),
				Options: &armresourcegraph.QueryRequestOptions{
					ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
					SkipToken:    skipToken,
					Top:          to.Ptr[int32](1000),
				},
			}

			res, err := a.client.Resources(ctx, req, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to query vulnerabilities for repository %s: %w", imageID.Repository, err)
			}

			if res.Data != nil {
				dataList, ok := res.Data.([]interface{})
				if !ok {
					return nil, fmt.Errorf("failed to decode ARG response data format")
				}
				for _, item := range dataList {
					if count >= maxVulns {
						// Log truncation rather than failing hard
						logger.L().Warning("truncated vulnerabilities", helpers.String("repository", imageID.Repository), helpers.Int("limit", maxVulns))
						break
					}

					row, ok := item.(map[string]interface{})
					if !ok {
						return nil, fmt.Errorf("malformed vulnerability row: expected map[string]interface{}, got %T", item)
					}

					vuln := Vulnerability{
						ID:          getStringSafe(row, "id"),
						Severity:    normalizeAzureSeverity(getStringSafe(row, "severity")),
						Description: getStringSafe(row, "description"),
						Links:       []string{},
					}

					// Try to get primary CVE if it exists
					if cves := getMultipleNestedStringSafe(row, "cve", "title"); len(cves) > 0 {
						for _, cve := range cves {
							if count >= maxVulns {
								break
							}
							newVuln := vuln
							newVuln.ID = cve
							report.Vulnerabilities = append(report.Vulnerabilities, newVuln)
							count++
						}
					} else {
						report.Vulnerabilities = append(report.Vulnerabilities, vuln)
						count++
					}
				}
			}

			if count >= maxVulns || res.SkipToken == nil || *res.SkipToken == "" {
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
		return nil, fmt.Errorf("azure client not initialized, call Login first")
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

func getMultipleNestedStringSafe(m map[string]interface{}, key1, key2 string) []string {
	var results []string
	if val1, ok := m[key1]; ok {
		if nested, ok := val1.([]interface{}); ok {
			for _, item := range nested {
				if obj, ok := item.(map[string]interface{}); ok {
					if str := getStringSafe(obj, key2); str != "" {
						results = append(results, str)
					}
				}
			}
		}
	}
	return results
}
