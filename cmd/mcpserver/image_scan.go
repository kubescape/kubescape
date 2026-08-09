package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
)

const defaultImageScanTimeout = 5 * time.Minute

type imageScanResponse struct {
	Image           string                 `json:"image"`
	TotalUniqueCVEs int                    `json:"total_vulnerabilities"`
	Severities      map[string]int         `json:"severities"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	Matches         []models.Match         `json:"matches,omitempty"`
}

func validateSeverity(sev string) error {
	if sev == "" {
		return nil
	}
	switch strings.ToLower(sev) {
	case "critical", "high", "medium", "low", "negligible", "unknown":
		return nil
	default:
		return fmt.Errorf("invalid severity %q: must be one of Critical, High, Medium, Low, Negligible, Unknown", sev)
	}
}

// validateImageReference validates that imageName is a valid remote image reference
// and not a local filesystem path or forbidden URI scheme.
func validateImageReference(imageName string) error {
	if imageName == "" {
		return fmt.Errorf("image_name argument is required and cannot be empty")
	}

	lower := strings.ToLower(imageName)

	// Block scheme prefixes that Syft/Grype resolve locally or on disk
	forbiddenPrefixes := []string{
		"dir:", "file:", "sbom:", "purl:", "cpe:", "pkg:", "oci-dir:", "oci-archive:",
		"docker-archive:", "docker-daemon:", "docker:", "podman:", "singularity:",
		"local-file:", "local-directory:", "daemon:", "containerd:", "image:", "oci-model:", "snap:",
	}
	for _, prefix := range forbiddenPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("invalid image reference %q: local filesystem and custom scheme references are not allowed", imageName)
		}
	}

	// Block relative or absolute local file paths
	if strings.HasPrefix(imageName, "/") || strings.HasPrefix(imageName, "./") || strings.HasPrefix(imageName, "../") {
		return fmt.Errorf("invalid image reference %q: local file paths are not allowed", imageName)
	}

	// Extract path component before tags/digests and check if it exists on local filesystem
	pathPart := strings.SplitN(strings.SplitN(imageName, ":", 2)[0], "@", 2)[0]
	if _, err := os.Stat(pathPart); err == nil {
		return fmt.Errorf("invalid image reference %q: resolves to a local file or directory", imageName)
	}
	if _, err := os.Stat(imageName); err == nil {
		return fmt.Errorf("invalid image reference %q: resolves to a local file or directory", imageName)
	}

	// Validate using go-containerregistry
	if _, err := name.ParseReference(imageName); err != nil {
		return fmt.Errorf("invalid image reference %q: %w", imageName, err)
	}

	return nil
}

func normalizeSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "negligible":
		return "Negligible"
	default:
		return "Unknown"
	}
}

func parseSeverityLevel(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "negligible":
		return 1
	default:
		return 0
	}
}

// processMatches deduplicates vulnerabilities by ID, normalizes severities,
// counts unique vulnerabilities per severity, and formats the response.
func processMatches(imageName string, matches []models.Match, includeMatches bool, minSeverity string) imageScanResponse {
	vulnerabilities := make([]models.Vulnerability, 0)
	filteredMatches := make([]models.Match, 0)
	seenVulns := make(map[string]bool)
	severities := make(map[string]int)

	minSevLevel := parseSeverityLevel(minSeverity)

	for _, m := range matches {
		sev := m.Vulnerability.Severity
		if sev == "" {
			sev = "Unknown"
		}
		sevNormalized := normalizeSeverity(sev)

		if parseSeverityLevel(sevNormalized) < minSevLevel {
			continue
		}

		if !seenVulns[m.Vulnerability.ID] {
			seenVulns[m.Vulnerability.ID] = true
			vuln := m.Vulnerability
			vuln.Severity = sevNormalized
			vulnerabilities = append(vulnerabilities, vuln)
			severities[sevNormalized]++
		}

		if includeMatches {
			m.Vulnerability.Severity = sevNormalized
			filteredMatches = append(filteredMatches, m)
		}
	}

	resp := imageScanResponse{
		Image:           imageName,
		TotalUniqueCVEs: len(vulnerabilities),
		Severities:      severities,
		Vulnerabilities: vulnerabilities,
	}
	if includeMatches {
		resp.Matches = filteredMatches
	}
	return resp
}

func (ksServer *KubescapeMcpserver) runImageScan(ctx context.Context, imageName, username, regSecret string, includeMatches bool, minSeverity string) ([]byte, error) {
	if err := validateImageReference(imageName); err != nil {
		return nil, err
	}

	if !ksServer.imageScanMu.TryLock() {
		return nil, fmt.Errorf("another container image scan is currently in progress; please wait for it to complete")
	}

	// Derive a bounded child context with a timeout covering service initialization and scan
	scanCtx, cancel := context.WithTimeout(ctx, defaultImageScanTimeout)
	defer cancel()

	logger.L().Info(fmt.Sprintf("Starting on-demand MCP container image scan for %s", imageName))

	svc, err := ksServer.getImageScanService(scanCtx)
	if err != nil {
		ksServer.imageScanMu.Unlock()
		return nil, fmt.Errorf("failed to get image scan service: %w", err)
	}

	creds := imagescan.RegistryCredentials{
		Username: username,
		Password: regSecret,
	}

	type result struct {
		data *cautils.ImageScanData
		err  error
	}

	ch := make(chan result, 1)
	go func() {
		defer ksServer.imageScanMu.Unlock()
		res, err := svc.Scan(scanCtx, imageName, creds, nil, nil)
		ch <- result{data: res, err: err}
	}()

	var scanResults *cautils.ImageScanData
	select {
	case <-scanCtx.Done():
		return nil, fmt.Errorf("container image scan timed out or was canceled: %w", scanCtx.Err())
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("failed to scan container image %s: %w", imageName, res.err)
		}
		scanResults = res.data
	}

	doc, err := models.NewDocument(
		clio.Identification{},
		scanResults.Packages,
		scanResults.Context,
		scanResults.Matches,
		scanResults.IgnoredMatches,
		scanResults.VulnerabilityProvider,
		nil,
		nil,
		models.DefaultSortStrategy,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vulnerability document: %w", err)
	}

	response := processMatches(imageName, doc.Matches, includeMatches, minSeverity)

	return json.Marshal(response)
}
