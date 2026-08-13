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
	if credentials.Username != "" || credentials.Password != "" || credentials.Token != "" {
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

	parts := strings.Split(a.registryHost, ".")
	registryName := parts[0]

	return ProcessImages(imageIDs,
		func(imageID ContainerImageIdentifier) (ContainerImageScanStatus, error) {
			status := ContainerImageScanStatus{
				ImageID:         imageID,
				IsScanAvailable: false,
				IsBomAvailable:  false,
			}

			if imageID.Hash == "" {
				return status, nil
			}

			if err := a.validateImageID(imageID); err != nil {
				logger.L().Warning("skipping image", helpers.String("repository", imageID.Repository), helpers.Error(err))
				return status, nil
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
				return status, fmt.Errorf("failed to query scan status for repository %s: %w", imageID.Repository, err)
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

			return status, nil
		},
	)
}

// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
func (a *AzureAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	if a.client == nil {
		return nil, fmt.Errorf("azure client not initialized, call Login first")
	}

	parts := strings.Split(a.registryHost, ".")
	registryName := parts[0]

	return ProcessImages(imageIDs,
		func(imageID ContainerImageIdentifier) (ContainerImageVulnerabilityReport, error) {
			report := ContainerImageVulnerabilityReport{
				ImageID:         imageID,
				Vulnerabilities: []Vulnerability{},
			}

			if imageID.Hash == "" {
				return report, nil
			}

			if err := a.validateImageID(imageID); err != nil {
				logger.L().Warning("skipping image", helpers.String("repository", imageID.Repository), helpers.Error(err))
				return report, nil
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
					return report, fmt.Errorf("failed to query vulnerabilities for repository %s: %w", imageID.Repository, err)
				}

				if res.Data != nil {
					dataList, ok := res.Data.([]interface{})
					if !ok {
						return report, fmt.Errorf("failed to decode ARG response data format for repository %s", imageID.Repository)
					}
					malformed := false
					for _, item := range dataList {
						if count >= maxVulns {
							// Log truncation rather than failing hard
							logger.L().Warning("truncated vulnerabilities", helpers.String("repository", imageID.Repository), helpers.Int("limit", maxVulns))
							break
						}

						row, ok := item.(map[string]interface{})
						if !ok {
							malformed = true
							break
						}

						vuln := Vulnerability{
							ID:          getStringSafe(row, "id"),
							Severity:    NormalizeSeverity(getStringSafe(row, "severity")),
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
					if malformed {
						return report, fmt.Errorf("malformed vulnerability row for repository %s", imageID.Repository)
					}
				}

				if count >= maxVulns || res.SkipToken == nil || *res.SkipToken == "" {
					break
				}
				skipToken = res.SkipToken
			}

			return report, nil
		},
	)
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
func (a *AzureAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	if a.client == nil {
		return nil, fmt.Errorf("azure client not initialized, call Login first")
	}
	return FetchImagesInformation(imageIDs)
}

// Destroy cleans up any persistent resources used by the adaptor.
func (a *AzureAdaptor) Destroy() error {
	return nil
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
