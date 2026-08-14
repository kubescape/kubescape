package imagescan

import (
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

// HarborAPI defines the interface for Harbor HTTP interactions to enable mocking
type HarborAPI interface {
	DoRequest(ctx context.Context, method, path string) ([]byte, error)
}

type harborAPIWrapper struct {
	baseURL    string
	username   string
	password   string
	token      string
	httpClient *http.Client
}

func (w *harborAPIWrapper) DoRequest(ctx context.Context, method, path string) ([]byte, error) {
	url := fmt.Sprintf("%s%s", w.baseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	} else if w.username != "" && w.password != "" {
		req.SetBasicAuth(w.username, w.password)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("harbor api returned status %d for %s", resp.StatusCode, path)
	}

	return io.ReadAll(resp.Body)
}

// HarborAdaptor implements IContainerImageVulnerabilityAdaptor for Harbor Container Registry.
type HarborAdaptor struct {
	client HarborAPI
	host   string
}

// NewHarborAdaptor creates a new Harbor adaptor instance.
func NewHarborAdaptor() *HarborAdaptor {
	return &HarborAdaptor{}
}

// Login authenticates with Harbor. The registry string should be the host (e.g. core.harbor.domain).
func (a *HarborAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	a.host = registry

	scheme := "https"
	if strings.HasPrefix(a.host, "http://") {
		scheme = "http"
		a.host = strings.TrimPrefix(a.host, "http://")
	} else {
		a.host = strings.TrimPrefix(a.host, "https://")
	}

	baseURL := fmt.Sprintf("%s://%s", scheme, a.host)

	wrapper := &harborAPIWrapper{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}

	if credentials.hasAuthenticator() {
		wrapper.username = credentials.Username
		wrapper.password = credentials.Password
		wrapper.token = credentials.Token
	}

	a.client = wrapper

	// Ping to verify connectivity. Note: /api/v2.0/systeminfo permits anonymous requests,
	// so this primarily validates that the Harbor endpoint is reachable and the URL is correct,
	// rather than strictly verifying the validity of the credentials for all projects.
	// We rely on actual vulnerability fetch calls to return 401/403 if credentials are invalid.
	_, err := a.client.DoRequest(ctx, http.MethodGet, "/api/v2.0/systeminfo")
	if err != nil {
		a.client = nil
		return fmt.Errorf("failed to connect to harbor at %s: %w", baseURL, err)
	}

	return nil
}

// DescribeAdaptor provides a string description of the adaptor for help purposes.
func (a *HarborAdaptor) DescribeAdaptor() string {
	return "Harbor Container Registry Vulnerability Adaptor"
}

// extractProjectAndRepo splits the image repository string (e.g. myproject/myrepo) into project and repository parts
func extractProjectAndRepo(repo string) (string, string, error) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid harbor repository format: expected project/repository, got %s", repo)
	}
	return parts[0], parts[1], nil
}

// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
func (a *HarborAdaptor) GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error) {
	if a.client == nil {
		return nil, fmt.Errorf("harbor client not initialized, call login first")
	}

	var statuses []ContainerImageScanStatus
	var aggErr error

	for _, imageID := range imageIDs {
		status := ContainerImageScanStatus{
			ImageID:         imageID,
			IsScanAvailable: false,
			IsBomAvailable:  false,
		}

		ref := imageID.Hash
		if ref == "" {
			ref = imageID.Tag
		}
		if ref == "" {
			statuses = append(statuses, status)
			continue
		}

		project, repo, err := extractProjectAndRepo(imageID.Repository)
		if err != nil {
			fetchErr := fmt.Errorf("failed to extract project from repository %s: %w", imageID.Repository, err)
			logger.L().Warning("skipping image scan status due to format error", helpers.Error(fetchErr))
			aggErr = errors.Join(aggErr, fetchErr)
			statuses = append(statuses, status)
			continue
		}

		// URL encode the repository name to handle nested repositories (e.g., myrepo/backend -> myrepo%2Fbackend)
		encodedRepo := strings.ReplaceAll(repo, "/", "%2F")
		path := fmt.Sprintf("/api/v2.0/projects/%s/repositories/%s/artifacts/%s?with_scan_overview=true", project, encodedRepo, ref)

		data, err := a.client.DoRequest(ctx, http.MethodGet, path)
		if err != nil {
			fetchErr := fmt.Errorf("failed to query scan status for repository %s: %w", repo, err)
			logger.L().Warning("skipping image scan status due to api error", helpers.Error(fetchErr))
			aggErr = errors.Join(aggErr, fetchErr)
			statuses = append(statuses, status)
			continue
		}

		var artifact struct {
			ScanOverview map[string]struct {
				ScanStatus string `json:"scan_status"`
				EndTime    string `json:"end_time"`
			} `json:"scan_overview"`
		}

		if err := json.Unmarshal(data, &artifact); err != nil {
			fetchErr := fmt.Errorf("failed to parse scan status payload for repository %s: %w", repo, err)
			logger.L().Warning("skipping image scan status due to payload error", helpers.Error(fetchErr))
			aggErr = errors.Join(aggErr, fetchErr)
			statuses = append(statuses, status)
			continue
		}

		if artifact.ScanOverview != nil {
			for _, overview := range artifact.ScanOverview {
				if overview.ScanStatus == "Success" {
					status.IsScanAvailable = true
					if t, err := time.Parse(time.RFC3339, overview.EndTime); err == nil {
						status.LastScanDate = t
					}
					break
				}
			}
		}

		statuses = append(statuses, status)
	}

	return statuses, aggErr
}

// normalizeHarborSeverity maps Harbor severity to Kubescape severity strings
func normalizeHarborSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "negligible", "none":
		return "Negligible"
	default:
		return "Unknown"
	}
}

// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
func (a *HarborAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	if a.client == nil {
		return nil, fmt.Errorf("harbor client not initialized, call login first")
	}

	var reports []ContainerImageVulnerabilityReport
	var aggErr error

	for _, imageID := range imageIDs {
		report := ContainerImageVulnerabilityReport{
			ImageID:         imageID,
			Vulnerabilities: []Vulnerability{},
		}

		ref := imageID.Hash
		if ref == "" {
			ref = imageID.Tag
		}
		if ref == "" {
			reports = append(reports, report)
			continue
		}

		project, repo, err := extractProjectAndRepo(imageID.Repository)
		if err != nil {
			fetchErr := fmt.Errorf("failed to extract project from repository %s: %w", imageID.Repository, err)
			logger.L().Warning("skipping image vulnerabilities due to format error", helpers.Error(fetchErr))
			aggErr = errors.Join(aggErr, fetchErr)
			reports = append(reports, report)
			continue
		}

		encodedRepo := strings.ReplaceAll(repo, "/", "%2F")
		path := fmt.Sprintf("/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", project, encodedRepo, ref)

		data, err := a.client.DoRequest(ctx, http.MethodGet, path)
		if err != nil {
			fetchErr := fmt.Errorf("failed to query vulnerabilities for repository %s: %w", repo, err)
			logger.L().Warning("skipping image vulnerabilities due to api error", helpers.Error(fetchErr))
			aggErr = errors.Join(aggErr, fetchErr)
			reports = append(reports, report)
			continue
		}

		var harborVulnPayload map[string]struct {
			Vulnerabilities []struct {
				ID          string   `json:"id"`
				Severity    string   `json:"severity"`
				Description string   `json:"description"`
				Links       []string `json:"links"`
			} `json:"vulnerabilities"`
		}

		if err := json.Unmarshal(data, &harborVulnPayload); err != nil {
			fetchErr := fmt.Errorf("failed to parse vulnerability payload for repository %s: %w", repo, err)
			logger.L().Warning("failed to parse vulnerability payload", helpers.Error(fetchErr))
			aggErr = errors.Join(aggErr, fetchErr)
			reports = append(reports, report)
			continue
		}

		for _, mimeTypeData := range harborVulnPayload {
			for _, v := range mimeTypeData.Vulnerabilities {
				vuln := Vulnerability{
					ID:          v.ID,
					Severity:    normalizeHarborSeverity(v.Severity),
					Description: v.Description,
					Links:       v.Links,
				}
				report.Vulnerabilities = append(report.Vulnerabilities, vuln)
			}
		}

		reports = append(reports, report)
	}

	return reports, aggErr
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
func (a *HarborAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	if a.client == nil {
		return nil, fmt.Errorf("harbor client not initialized, call login first")
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
func (a *HarborAdaptor) Destroy() error {
	// The HTTP client automatically closes idle connections
	return nil
}
