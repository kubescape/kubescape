package imagescan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// GitlabAPI defines the interface for GitLab GraphQL interactions to enable mocking
type GitlabAPI interface {
	DoGraphQL(ctx context.Context, query string, variables map[string]interface{}) ([]byte, error)
}

type gitlabAPIWrapper struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func (w *gitlabAPIWrapper) DoGraphQL(ctx context.Context, query string, variables map[string]interface{}) ([]byte, error) {
	body, err := json.Marshal(map[string]interface{}{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.baseURL+"/api/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(bodyBytes)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		return nil, fmt.Errorf("gitlab graphql api returned status %d: %s", resp.StatusCode, snippet)
	}

	return bodyBytes, nil
}

// GitlabAdaptor implements IContainerImageVulnerabilityAdaptor for GitLab Container Registry.
type GitlabAdaptor struct {
	client GitlabAPI
}

// NewGitlabAdaptor creates a new GitLab adaptor instance.
func NewGitlabAdaptor() *GitlabAdaptor {
	return &GitlabAdaptor{}
}

// Login authenticates with GitLab GraphQL API.
func (a *GitlabAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	if credentials.Token == "" {
		return fmt.Errorf("gitlab adaptor requires a personal or project access token; username/password is not supported for the GraphQL API")
	}

	registry = strings.TrimRight(registry, "/")
	host := strings.TrimPrefix(strings.TrimPrefix(registry, "https://"), "http://")
	scheme := "https"
	if strings.HasPrefix(registry, "http://") {
		scheme = "http"
	}

	baseURL := fmt.Sprintf("%s://%s", scheme, host)

	wrapper := &gitlabAPIWrapper{
		baseURL:    baseURL,
		token:      credentials.Token,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}

	data, err := wrapper.DoGraphQL(ctx, `query { currentUser { username } }`, nil)
	if err != nil {
		return fmt.Errorf("failed to connect to gitlab graphql api at %s: %w", wrapper.baseURL, err)
	}

	var loginResp struct {
		Data struct {
			CurrentUser *struct {
				Username string `json:"username"`
			} `json:"currentUser"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(data, &loginResp); err != nil {
		return fmt.Errorf("failed to parse login response: %w", err)
	}

	if len(loginResp.Errors) > 0 {
		return fmt.Errorf("graphql error during login: %s", loginResp.Errors[0].Message)
	}

	if loginResp.Data.CurrentUser == nil || loginResp.Data.CurrentUser.Username == "" {
		return fmt.Errorf("invalid token or insufficient scopes (currentUser is null)")
	}

	a.client = wrapper
	return nil
}

// DescribeAdaptor provides a string description of the adaptor for help purposes.
func (a *GitlabAdaptor) DescribeAdaptor() string {
	return "GitLab Container Registry Vulnerability Adaptor"
}

// splitGitLabProjectPath splits a repository string into the project's GraphQL
// fullPath and the trailing container image name.
func splitGitLabProjectPath(repo string) (string, string, error) {
	repo = strings.TrimPrefix(repo, "/")
	if strings.Count(repo, "/") < 2 {
		return "", "", fmt.Errorf("invalid gitlab repository format: expected at least group/project/image, got %s", repo)
	}
	idx := strings.LastIndex(repo, "/")
	if idx <= 0 || idx == len(repo)-1 {
		return "", "", fmt.Errorf("invalid gitlab repository format: expected at least group/project/image, got %s", repo)
	}
	return repo[:idx], repo[idx+1:], nil
}

// normalizeGitLabSeverity maps GitLab severity to Kubescape severity strings
func normalizeGitLabSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	case "LOW":
		return "Low"
	case "INFO":
		return "Negligible"
	default:
		return "Unknown"
	}
}

type gitlabVulnerabilityNode struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    struct {
		Image string `json:"image"`
	} `json:"location"`
	Links []struct {
		URL string `json:"url"`
	} `json:"links"`
}

type gitlabGraphQLResponse struct {
	Data struct {
		Project *struct {
			Vulnerabilities struct {
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []gitlabVulnerabilityNode `json:"nodes"`
			} `json:"vulnerabilities"`
		} `json:"project"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type scanCacheEntry struct {
	isAvailable bool
	err         error
}

// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
func (a *GitlabAdaptor) GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error) {
	if a.client == nil {
		return nil, fmt.Errorf("gitlab client not initialized, call login first")
	}

	var statuses []ContainerImageScanStatus
	var aggErr error
	cache := make(map[string]scanCacheEntry)

	for _, imageID := range imageIDs {
		status := ContainerImageScanStatus{
			ImageID:         imageID,
			IsScanAvailable: false,
			IsBomAvailable:  false,
		}

		fullPath, _, err := splitGitLabProjectPath(imageID.Repository)
		if err != nil {
			fetchErr := fmt.Errorf("failed to parse gitlab path: %w", err)
			logger.L().Warning("skipping image scan status due to format error", helpers.Error(fetchErr))
			aggErr = errors.Join(aggErr, fetchErr)
			statuses = append(statuses, status)
			continue
		}

		if entry, ok := cache[fullPath]; ok {
			status.IsScanAvailable = entry.isAvailable
			if entry.err != nil {
				aggErr = errors.Join(aggErr, entry.err)
			}
			statuses = append(statuses, status)
			continue
		}

		query := `
			query($fullPath: ID!) {
				project(fullPath: $fullPath) {
					vulnerabilities(reportType: [CONTAINER_SCANNING], first: 1) {
						nodes {
							title
						}
					}
				}
			}
		`

		variables := map[string]interface{}{
			"fullPath": fullPath,
		}

		data, err := a.client.DoGraphQL(ctx, query, variables)
		if err != nil {
			fetchErr := fmt.Errorf("failed to query scan status for repository %s: %w", fullPath, err)
			logger.L().Warning("skipping image scan status due to api error", helpers.Error(fetchErr))
			cache[fullPath] = scanCacheEntry{isAvailable: false, err: fetchErr}
			aggErr = errors.Join(aggErr, fetchErr)
			statuses = append(statuses, status)
			continue
		}

		var resp gitlabGraphQLResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			fetchErr := fmt.Errorf("failed to parse scan status payload: %w", err)
			logger.L().Warning("skipping image scan status due to payload error", helpers.Error(fetchErr))
			cache[fullPath] = scanCacheEntry{isAvailable: false, err: fetchErr}
			aggErr = errors.Join(aggErr, fetchErr)
			statuses = append(statuses, status)
			continue
		}

		if len(resp.Errors) > 0 {
			fetchErr := fmt.Errorf("graphql error: %s", resp.Errors[0].Message)
			logger.L().Warning("skipping image scan status due to graphql error", helpers.Error(fetchErr))
			cache[fullPath] = scanCacheEntry{isAvailable: false, err: fetchErr}
			aggErr = errors.Join(aggErr, fetchErr)
			statuses = append(statuses, status)
			continue
		}

		if resp.Data.Project == nil {
			fetchErr := fmt.Errorf("project not found or permission denied (project is null)")
			logger.L().Warning("skipping image scan status due to missing project", helpers.Error(fetchErr))
			cache[fullPath] = scanCacheEntry{isAvailable: false, err: fetchErr}
			aggErr = errors.Join(aggErr, fetchErr)
			statuses = append(statuses, status)
			continue
		}

		cache[fullPath] = scanCacheEntry{isAvailable: true, err: nil}
		status.IsScanAvailable = true
		statuses = append(statuses, status)
	}

	return statuses, aggErr
}

type vulnCacheEntry struct {
	nodes []gitlabVulnerabilityNode
	err   error
}

const maxGitLabVulnerabilityPages = 1000

func nextGitLabVulnerabilityCursor(hasNextPage bool, endCursor string, seen map[string]struct{}, pagesFetched int) (string, bool, error) {
	if !hasNextPage {
		return "", false, nil
	}
	if endCursor == "" {
		return "", false, fmt.Errorf("gitlab vulnerability pagination reported another page without an end cursor")
	}
	if _, exists := seen[endCursor]; exists {
		return "", false, fmt.Errorf("gitlab vulnerability pagination repeated cursor %q", endCursor)
	}
	if pagesFetched >= maxGitLabVulnerabilityPages {
		return "", false, fmt.Errorf("gitlab vulnerability pagination exceeded the %d-page safety limit", maxGitLabVulnerabilityPages)
	}

	seen[endCursor] = struct{}{}
	return endCursor, true, nil
}

// imageMatches provides a boundary-safe match for the image location.
func imageMatches(locationImage string, imageID ContainerImageIdentifier) bool {
	if imageID.Hash != "" {
		expectedSuffix := imageID.Repository + "@" + imageID.Hash
		if locationImage == expectedSuffix || strings.HasSuffix(locationImage, "/"+expectedSuffix) {
			return true
		}
	}

	if imageID.Tag != "" {
		expectedSuffix := imageID.Repository + ":" + imageID.Tag
		if locationImage == expectedSuffix || strings.HasSuffix(locationImage, "/"+expectedSuffix) {
			return true
		}
	}

	return false
}

// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
func (a *GitlabAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	if a.client == nil {
		return nil, fmt.Errorf("gitlab client not initialized, call login first")
	}

	var reports []ContainerImageVulnerabilityReport
	var aggErr error
	cache := make(map[string]vulnCacheEntry)

	for _, imageID := range imageIDs {
		report := ContainerImageVulnerabilityReport{
			ImageID:         imageID,
			Vulnerabilities: []Vulnerability{},
		}

		fullPath, _, err := splitGitLabProjectPath(imageID.Repository)
		if err != nil {
			fetchErr := fmt.Errorf("failed to parse gitlab path: %w", err)
			logger.L().Warning("skipping image vulnerabilities due to format error", helpers.Error(fetchErr))
			aggErr = errors.Join(aggErr, fetchErr)
			reports = append(reports, report)
			continue
		}

		var projectNodes []gitlabVulnerabilityNode

		if entry, ok := cache[fullPath]; ok {
			projectNodes = entry.nodes
			if entry.err != nil {
				aggErr = errors.Join(aggErr, entry.err)
			}
		} else {
			query := `
				query($fullPath: ID!, $after: String) {
					project(fullPath: $fullPath) {
						vulnerabilities(reportType: [CONTAINER_SCANNING], after: $after) {
							pageInfo {
								hasNextPage
								endCursor
							}
							nodes {
								title
								severity
								description
								location {
									... on VulnerabilityLocationContainerScanning {
										image
									}
								}
								links {
									url
								}
							}
						}
					}
				}
			`

			var afterCursor string
			hasNextPage := true
			var fetchErr error
			seenCursors := make(map[string]struct{})
			pagesFetched := 0

			for hasNextPage {
				variables := map[string]interface{}{
					"fullPath": fullPath,
				}
				if afterCursor != "" {
					variables["after"] = afterCursor
				}

				data, err := a.client.DoGraphQL(ctx, query, variables)
				if err != nil {
					fetchErr = fmt.Errorf("failed to query vulnerabilities for repository %s: %w", fullPath, err)
					logger.L().Warning("skipping image vulnerabilities due to api error", helpers.Error(fetchErr))
					break
				}

				var resp gitlabGraphQLResponse
				if err := json.Unmarshal(data, &resp); err != nil {
					fetchErr = fmt.Errorf("failed to parse vulnerability payload: %w", err)
					logger.L().Warning("failed to parse vulnerability payload", helpers.Error(fetchErr))
					break
				}

				if len(resp.Errors) > 0 {
					fetchErr = fmt.Errorf("graphql error: %s", resp.Errors[0].Message)
					logger.L().Warning("failed to fetch vulnerabilities due to graphql error", helpers.Error(fetchErr))
					break
				}

				if resp.Data.Project == nil {
					fetchErr = fmt.Errorf("project not found or permission denied (project is null)")
					logger.L().Warning("failed to fetch vulnerabilities due to missing project", helpers.Error(fetchErr))
					break
				}

				projectNodes = append(projectNodes, resp.Data.Project.Vulnerabilities.Nodes...)
				pagesFetched++

				afterCursor, hasNextPage, fetchErr = nextGitLabVulnerabilityCursor(
					resp.Data.Project.Vulnerabilities.PageInfo.HasNextPage,
					resp.Data.Project.Vulnerabilities.PageInfo.EndCursor,
					seenCursors,
					pagesFetched,
				)
				if fetchErr != nil {
					logger.L().Warning("stopping invalid gitlab vulnerability pagination", helpers.Error(fetchErr))
					break
				}
			}

			cache[fullPath] = vulnCacheEntry{nodes: projectNodes, err: fetchErr}
			if fetchErr != nil {
				aggErr = errors.Join(aggErr, fetchErr)
			}
		}

		for _, node := range projectNodes {
			if !imageMatches(node.Location.Image, imageID) {
				if imageID.Tag == "" && imageID.Hash != "" && strings.Contains(node.Location.Image, imageID.Repository) {
					logger.L().Debug("skipped vulnerability because gitlab location lacked matching digest (API limitation?)", helpers.String("image", node.Location.Image), helpers.String("digest", imageID.Hash))
				}
				continue
			}

			var links []string
			for _, l := range node.Links {
				links = append(links, l.URL)
			}

			vuln := Vulnerability{
				ID:          node.Title,
				Severity:    normalizeGitLabSeverity(node.Severity),
				Description: node.Description,
				Links:       links,
			}
			report.Vulnerabilities = append(report.Vulnerabilities, vuln)
		}

		reports = append(reports, report)
	}

	return reports, aggErr
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
// Note: The GitLab GraphQL API does not expose SBOM data, so this always returns an empty BOM.
func (a *GitlabAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	if a.client == nil {
		return nil, fmt.Errorf("gitlab client not initialized, call login first")
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

// Destroy cleans up any persistent resources used by the adaptor.
func (a *GitlabAdaptor) Destroy() error {
	return nil
}
