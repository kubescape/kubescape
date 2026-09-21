package imagescan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

var _ IContainerImageVulnerabilityAdaptor = (*AzureAdaptor)(nil)

var validKQLInputRegex = regexp.MustCompile(`^[a-zA-Z0-9.\-_/:]+$`)

const (
	maxAzureVulnerabilities    = 1000
	maxAzureVulnerabilityPages = 50
)

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

type azureCredentialProvider func(options *azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error)
type azureClientFactory func(cred azcore.TokenCredential, options *arm.ClientOptions) (AzureAPI, error)

// AzureAdaptor implements IContainerImageVulnerabilityAdaptor for Azure Container Registry (ACR).
type AzureAdaptor struct {
	client        AzureAPI
	registryHost  string
	credProvider  azureCredentialProvider
	clientFactory azureClientFactory
}

// NewAzureAdaptor creates a new Azure adaptor instance.
func NewAzureAdaptor() *AzureAdaptor {
	return &AzureAdaptor{
		credProvider: newDefaultAzureCredential,
		clientFactory: func(cred azcore.TokenCredential, options *arm.ClientOptions) (AzureAPI, error) {
			c, err := armresourcegraph.NewClient(cred, options)
			if err != nil {
				return nil, err
			}
			return &azureAPIWrapper{client: c}, nil
		},
	}
}

// newDefaultAzureCredential builds the Azure credential chain shared by
// AzureAdaptor (querying Azure Resource Graph, above) and newACRKeychain
// (authenticating pulls from ACR, below): azidentity.NewDefaultAzureCredential's
// full chain, in order - environment (service principal client secret,
// client certificate, or username/password), workload identity federation,
// managed identity (system- or user-assigned), then Azure CLI, Azure
// Developer CLI, and Azure PowerShell sessions.
func newDefaultAzureCredential(options *azidentity.DefaultAzureCredentialOptions) (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(options)
}

// resolveAzureCloudConfig maps an ACR hostname to its Azure cloud. Azure
// Germany (which would have used .azurecr.de) was retired in October 2021
// and is intentionally not handled here.
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

	cred, err := a.credProvider(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: clientOpts,
	})
	if err != nil {
		return fmt.Errorf("unable to load azure credentials: %w", err)
	}

	c, err := a.clientFactory(cred, &arm.ClientOptions{
		ClientOptions: clientOpts,
	})
	if err != nil {
		return fmt.Errorf("unable to load azure resource graph client: %w", err)
	}
	a.client = c

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
				return status, err
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
				return report, err
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
			seenSkipTokens := make(map[string]struct{})
			count := 0

			for pagesFetched := 0; ; pagesFetched++ {
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
						if count >= maxAzureVulnerabilities {
							// Log truncation rather than failing hard
							logger.L().Warning("truncated vulnerabilities", helpers.String("repository", imageID.Repository), helpers.Int("limit", maxAzureVulnerabilities))
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
								if count >= maxAzureVulnerabilities {
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

				if count >= maxAzureVulnerabilities {
					break
				}

				nextToken, hasNextPage, cursorErr := nextAzureVulnerabilityToken(
					res.SkipToken,
					seenSkipTokens,
					pagesFetched+1,
				)
				if cursorErr != nil {
					return report, fmt.Errorf("failed to query vulnerabilities for repository %s: %w", imageID.Repository, cursorErr)
				}
				if !hasNextPage {
					break
				}
				skipToken = to.Ptr(nextToken)
			}

			return report, nil
		},
	)
}

// nextAzureVulnerabilityToken decides whether another Resource Graph request
// can make progress. Skip tokens are opaque, but they must change between
// pages. Reusing any token already seen means the service has formed a cycle;
// continuing would append duplicate findings until the page cap is reached.
func nextAzureVulnerabilityToken(skipToken *string, seen map[string]struct{}, pagesFetched int) (string, bool, error) {
	if skipToken == nil || *skipToken == "" {
		return "", false, nil
	}

	token := *skipToken
	if strings.TrimSpace(token) == "" {
		return "", false, fmt.Errorf("azure resource graph pagination returned a blank skip token")
	}
	if _, exists := seen[token]; exists {
		return "", false, fmt.Errorf("azure resource graph pagination repeated skip token %q", token)
	}
	if pagesFetched >= maxAzureVulnerabilityPages {
		return "", false, fmt.Errorf("exceeded max pages (%d) fetching azure vulnerabilities", maxAzureVulnerabilityPages)
	}

	seen[token] = struct{}{}
	return token, true, nil
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

// --- Azure Container Registry image-pull authentication ---
//
// This is unrelated to AzureAdaptor above: AzureAdaptor asks Azure Resource
// Graph for scan results Microsoft Defender for Cloud already produced for
// an image already in ACR. newACRKeychain, instead, is what lets Kubescape's
// own pull-and-scan path (Service.ScanWithOptions in imagescan.go)
// authenticate to ACR in the first place. It shares newDefaultAzureCredential
// and resolveAzureCloudConfig with AzureAdaptor above, so it supports every
// auth method AzureAdaptor.Login does: service principal (client secret,
// client certificate, or username/password), workload identity federation,
// managed identity (system- or user-assigned), and Azure CLI/Developer
// CLI/PowerShell sessions.
//
// All cloud-provider-specific keychain code belongs here (or in a sibling
// *_adaptor.go, for another provider) - imagescan.go stays generic and only
// ever calls newRegistryKeychain(), never a provider directly.

// newRegistryKeychain composes the registry credential fallback used when no
// explicit RegistryCredentials/imagePullSecret matches a target registry.
// This mirrors the composition pattern documented by go-containerregistry
// itself (authn.NewMultiKeychain(authn.DefaultKeychain, google.Keychain,
// authn.NewKeychainFromHelper(ecr.ECRHelper{...}), ...)) - one flat,
// build-once list, so adding another cloud provider (e.g. AWS ECR via
// authn.NewKeychainFromHelper(ecr.ECRHelper{...}), or GKE/Artifact Registry
// via google.Keychain) is a matter of adding one more entry here, not a
// struct or function-signature change elsewhere.
//
// authn.DefaultKeychain (docker config / credential helpers on $PATH) is
// checked before any cloud-specific keychain: authn.NewMultiKeychain stops
// at the first non-anonymous result without verifying it actually works, so
// a deliberately configured docker login must take priority over an ambient
// cloud identity that merely happens to be present in the environment.
func newRegistryKeychain() authn.Keychain {
	return authn.NewMultiKeychain(
		authn.DefaultKeychain,
		newACRKeychain(),
	)
}

// acrKeychainRefreshInterval bounds how long a single already-resolved ACR
// authenticator is reused by a later Authorization() call on that same
// authenticator (see authn.RefreshingKeychain). It does NOT cache across
// separate images: authn.RefreshingKeychain.Resolve calls the wrapped
// keychain fresh every time, so a --scan-images run over N images still
// does a fresh Azure AD + /oauth2/exchange round trip per image, each
// bounded by httpClient's own timeout below.
const acrKeychainRefreshInterval = 30 * time.Minute

// newACRKeychain returns an authn.Keychain that authenticates to Azure
// Container Registry (*.azurecr.io/.cn/.us). It resolves to authn.Anonymous
// - not an error - for any other registry or when no Azure credential is
// available, so it's safe to compose with other keychains via
// authn.NewMultiKeychain without breaking non-ACR pulls.
func newACRKeychain() authn.Keychain {
	return authn.RefreshingKeychain(&azureACRKeychain{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			// The exchange POST carries an AAD access token in its body,
			// which Go's client preserves across 307/308 redirects since
			// the request body is replayable (strings.NewReader supplies
			// GetBody). Refuse to follow any redirect so that token can
			// never be replayed to a different host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		credProvider: func(cloudConfig cloud.Configuration) (azcore.TokenCredential, error) {
			return newDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
				ClientOptions: azcore.ClientOptions{Cloud: cloudConfig},
			})
		},
	}, acrKeychainRefreshInterval)
}

// azureACRKeychain implements authn.Keychain for Azure Container Registry.
var _ authn.Keychain = (*azureACRKeychain)(nil)

type azureACRKeychain struct {
	httpClient   *http.Client
	credProvider func(cloudConfig cloud.Configuration) (azcore.TokenCredential, error)
}

// Resolve implements authn.Keychain.
func (k *azureACRKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	registry := target.RegistryStr()

	cloudConfig, err := resolveAzureCloudConfig(registry)
	if err != nil {
		// Not a registry we recognize as ACR.
		return authn.Anonymous, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	identityToken, err := k.acrIdentityToken(ctx, registry, cloudConfig)
	if err != nil {
		// Soft-fail: let the caller fall back to the next keychain (e.g. the
		// default docker-config keychain) instead of aborting the pull.
		logger.L().Debug("azure keychain: failed to obtain ACR credentials",
			helpers.String("registry", registry), helpers.Error(err))
		return authn.Anonymous, nil
	}

	return authn.FromConfig(authn.AuthConfig{IdentityToken: identityToken}), nil
}

// acrIdentityToken acquires an ARM-scoped Azure AD access token for
// registry's cloud, then exchanges it for an ACR refresh token. The
// resulting refresh token is presented to go-containerregistry as an
// authn.AuthConfig.IdentityToken, which drives the standard OAuth2
// refresh_token flow against the registry's own /oauth2/token endpoint -
// the same exchange `az acr login` performs.
func (k *azureACRKeychain) acrIdentityToken(ctx context.Context, registry string, cloudConfig cloud.Configuration) (string, error) {
	cred, err := k.credProvider(cloudConfig)
	if err != nil {
		return "", fmt.Errorf("no Azure credential available: %w", err)
	}

	armConf, ok := cloudConfig.Services[cloud.ResourceManager]
	if !ok || armConf.Audience == "" {
		return "", fmt.Errorf("no Azure Resource Manager audience configured for this cloud")
	}

	aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{armConf.Audience + "/.default"}})
	if err != nil {
		return "", fmt.Errorf("failed to acquire Azure AD access token: %w", err)
	}

	return k.exchangeForACRRefreshToken(ctx, registry, aadToken.Token, tenantIDFromToken(aadToken.Token))
}

// exchangeForACRRefreshToken exchanges an AAD access token for an ACR
// refresh token via the registry's /oauth2/exchange endpoint.
func (k *azureACRKeychain) exchangeForACRRefreshToken(ctx context.Context, registry, aadAccessToken, tenantID string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "access_token")
	form.Set("service", registry)
	form.Set("access_token", aadAccessToken)
	if tenantID != "" {
		form.Set("tenant", tenantID)
	}

	exchangeURL := "https://" + registry + "/oauth2/exchange"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to build ACR token exchange request for %s: %w", registry, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to reach ACR token exchange endpoint for %s: %w", registry, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read ACR token exchange response from %s: %w", registry, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ACR token exchange for %s failed with status %d: %s", registry, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var exchangeResp struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &exchangeResp); err != nil {
		return "", fmt.Errorf("failed to parse ACR token exchange response from %s: %w", registry, err)
	}
	if exchangeResp.RefreshToken == "" {
		return "", fmt.Errorf("ACR token exchange for %s returned no refresh token", registry)
	}

	return exchangeResp.RefreshToken, nil
}

// tenantIDFromToken extracts the "tid" (tenant ID) claim from an AAD JWT
// access token, without verifying its signature - the token was already
// obtained from a trusted azidentity credential; this only reads a claim off
// it, to tell the ACR exchange endpoint which tenant the token belongs to
// regardless of which of the six DefaultAzureCredential methods produced it
// (an active `az login` session, for instance, need not match any
// AZURE_TENANT_ID environment variable). Returns "" if the token can't be
// parsed; the exchange endpoint treats an absent tenant as "infer it from
// the token", which is sufficient for single-tenant scenarios.
func tenantIDFromToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload := parts[1]
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	var claims struct {
		TenantID string `json:"tid"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}
	return claims.TenantID
}
