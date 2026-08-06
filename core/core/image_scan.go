package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/distribution/reference"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
)

// Data structure to represent attributes
type Attributes struct {
	Registry     string `json:"registry"`
	Organization string `json:"organization,omitempty"`
	ImageName    string `json:"imageName"`
	ImageTag     string `json:"imageTag,omitempty"`
}

// Data structure for a target
type Target struct {
	DesignatorType string     `json:"designatorType"`
	Attributes     Attributes `json:"attributes"`
}

// Data structure for metadata
type Metadata struct {
	Name string `json:"name"`
}

// Data structure for vulnerabilities and severities
type VulnerabilitiesIgnorePolicy struct {
	Metadata        Metadata `json:"metadata"`
	Kind            string   `json:"kind"`
	Targets         []Target `json:"targets"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Severities      []string `json:"severities"`
}

// Loads exception policies from exceptions json object.
func GetImageExceptionsFromFile(filePath string) ([]VulnerabilitiesIgnorePolicy, error) {
	// Read the JSON file
	jsonFile, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading exceptions file: %w", err)
	}

	// Unmarshal the JSON data into an array of VulnerabilitiesIgnorePolicy
	var policies []VulnerabilitiesIgnorePolicy
	err = json.Unmarshal(jsonFile, &policies)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling exceptions file: %w", err)
	}

	return policies, nil
}

// This function will identify the registry, organization and image tag from the image name
func getAttributesFromImage(imgName string) (Attributes, error) {
	ref, err := reference.ParseNormalizedNamed(imgName)
	if err != nil {
		return Attributes{}, err
	}

	registry := reference.Domain(ref)
	path := reference.Path(ref)

	organization := ""
	imageName := path
	if idx := strings.LastIndex(path, "/"); idx != -1 {
		organization = path[:idx]
		imageName = path[idx+1:]
	}

	imageTag := "latest"
	if tagged, ok := ref.(reference.Tagged); ok {
		imageTag = tagged.Tag()
	} else if digested, ok := ref.(reference.Digested); ok {
		// No explicit tag on a digest-pinned reference: fall back to the
		// digest as ImageTag (deliberate choice, not Docker/OCI reference
		// semantics - Docker resolves a "name:tag@digest" reference by the
		// digest, ignoring the tag, but for *exception-policy matching* the
		// tag the user wrote is what they meant to target). This means an
		// exception policy that targets a specific ImageTag (e.g. "v3.*")
		// cannot match a purely digest-pinned scan, since ImageTag will be
		// the digest instead; only Registry/Organization/ImageName targets
		// (and an ImageTag target of "" - "any tag") can match it.
		imageTag = digested.Digest().String()
	}

	attributes := Attributes{
		Registry:     registry,
		Organization: organization,
		ImageName:    imageName,
		ImageTag:     imageTag,
	}

	return attributes, nil
}

// Checks if the target string matches the regex pattern
func regexStringMatch(pattern, target string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to generate regular expression: %s", err))
		return false
	}

	if re.MatchString(target) {
		return true
	}

	return false
}

// Compares the registry, organization, image name, image tag against the targets specified
// in the exception policy object to check if the image being scanned qualifies for an
// exception policy.
func isTargetImage(targets []Target, attributes Attributes) bool {
	for _, target := range targets {
		if regexStringMatch(target.Attributes.Registry, attributes.Registry) && regexStringMatch(target.Attributes.Organization, attributes.Organization) && regexStringMatch(target.Attributes.ImageName, attributes.ImageName) && regexStringMatch(target.Attributes.ImageTag, attributes.ImageTag) {
			return true
		}
	}

	return false
}

// Generates a list of unique CVE-IDs and the severities which are to be excluded for
// the image being scanned.
func getUniqueVulnerabilitiesAndSeverities(policies []VulnerabilitiesIgnorePolicy, image string) ([]string, []string) {
	// Create maps with slices as values to store unique vulnerabilities and severities (case-insensitive)
	uniqueVulns := make(map[string][]string)
	uniqueSevers := make(map[string][]string)

	imageAttributes, err := getAttributesFromImage(image)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to generate image attributes: %s", err))
	}

	// Iterate over each policy and its vulnerabilities/severities
	for _, policy := range policies {
		// Include the exceptions only if the image is one of the targets
		if isTargetImage(policy.Targets, imageAttributes) {
			for _, vulnerability := range policy.Vulnerabilities {
				// grype's IgnoreRule matching is case-sensitive and advisory
				// sources do not share a single casing convention: CVE IDs
				// are uppercase, while GHSA IDs keep a lowercase suffix
				// (e.g. "GHSA-jc7w-c686-c4v9"). Emit the trimmed original
				// casing plus the uppercased and lowercased forms so users
				// can list the ID in any casing without the filter silently
				// missing the match (kubescape issue #1870).
				vulnerability = strings.TrimSpace(vulnerability)
				if vulnerability == "" {
					continue
				}
				uniqueVulns[vulnerability] = append(uniqueVulns[vulnerability], vulnerability)
				vulnerabilityUppercase := strings.ToUpper(vulnerability)
				if vulnerabilityUppercase != vulnerability {
					uniqueVulns[vulnerabilityUppercase] = append(uniqueVulns[vulnerabilityUppercase], vulnerability)
				}
				vulnerabilityLowercase := strings.ToLower(vulnerability)
				if vulnerabilityLowercase != vulnerability && vulnerabilityLowercase != vulnerabilityUppercase {
					uniqueVulns[vulnerabilityLowercase] = append(uniqueVulns[vulnerabilityLowercase], vulnerability)
				}
			}

			for _, severity := range policy.Severities {
				// Add to slice directly
				severityUppercase := strings.ToUpper(severity)
				uniqueSevers[severityUppercase] = append(uniqueSevers[severityUppercase], severity)
			}
		}
	}

	// Extract unique keys (which are unique vulnerabilities/severities) and their slices
	uniqueVulnsList := make([]string, 0, len(uniqueVulns))
	for vuln := range uniqueVulns {
		uniqueVulnsList = append(uniqueVulnsList, vuln)
	}

	uniqueSeversList := make([]string, 0, len(uniqueSevers))
	for sever := range uniqueSevers {
		uniqueSeversList = append(uniqueSeversList, sever)
	}

	return uniqueVulnsList, uniqueSeversList
}

// applyRegistryMapping replaces the registry part of the image name if a match
// is found in the provided mapping. The returned bool indicates whether a
// mapping key actually matched; callers should only retry when matched is true.
func applyRegistryMapping(imgName string, registryMapping map[string]string) (string, bool, error) {
	if len(registryMapping) == 0 {
		return imgName, false, nil
	}
	canonicalImageName, err := cautils.NormalizeImageName(imgName)
	if err != nil {
		return "", false, err
	}
	tokens := strings.Split(canonicalImageName, "/")
	registry := tokens[0]
	if altRegistry, ok := registryMapping[registry]; ok {
		tokens[0] = altRegistry
		mappedName := strings.Join(tokens, "/")
		if _, err := reference.ParseNormalizedNamed(mappedName); err != nil {
			return "", false, fmt.Errorf("invalid image reference after applying registry mapping: %w", err)
		}
		return mappedName, true, nil
	}
	return imgName, false, nil
}

// isResolutionError checks if the error is related to unreachable registry hosts
// (DNS resolution failures, connection refused, timeouts). It uses typed error
// checks first and falls back to substring matching for wrapped errors.
func isResolutionError(err error) bool {
	if err == nil {
		return false
	}

	// Typed error checks — stable across Go and library versions.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Belt-and-braces: substring fallback for deeply wrapped errors where
	// the typed original has been lost.
	errStr := err.Error()
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout")
}

// scanWithRegistryMapping attempts to scan an image and, on a resolution error,
// retries using a mapped registry if one is configured. It returns the scan
// results or a combined error preserving both the original and fallback context.
type imageScanService interface {
	Scan(context.Context, string, imagescan.RegistryCredentials, []string, []string) (*cautils.ImageScanData, error)
}

func scanWithRegistryMapping(
	ctx context.Context,
	svc imageScanService,
	img string,
	creds imagescan.RegistryCredentials,
	registryMapping map[string]string,
	vulnExceptions, sevExceptions []string,
) (*cautils.ImageScanData, error) {
	scanData, err := svc.Scan(ctx, img, creds, vulnExceptions, sevExceptions)
	if err == nil {
		return scanData, nil
	}

	if len(registryMapping) == 0 || !isResolutionError(err) {
		return nil, err
	}

	logger.L().Warning(fmt.Sprintf("Failed to scan image %s: %s. Trying registry mapping...", img, err))

	mappedImage, matched, mapErr := applyRegistryMapping(img, registryMapping)
	if mapErr != nil {
		return nil, fmt.Errorf("scan failed for %s (%w) and failed to construct mapped image: %w", img, err, mapErr)
	}
	if !matched {
		return nil, err
	}

	logger.L().Info(fmt.Sprintf("Scanning mapped image %s (original: %s)...", mappedImage, img))
	scanData, fallbackErr := svc.Scan(ctx, mappedImage, creds, vulnExceptions, sevExceptions)
	if fallbackErr != nil {
		return nil, fmt.Errorf("scan failed for %s (%w) and for mapped image %s: %w", img, err, mappedImage, fallbackErr)
	}
	return scanData, nil
}

func (ks *Kubescape) ScanImage(imgScanInfo *ksmetav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	logger.L().Start(fmt.Sprintf("Scanning image %s...", imgScanInfo.Image))

	distCfg, installCfg, _, err := imagescan.NewDefaultDBConfig(scanInfo.ListingURL)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Invalid Grype database URL '%s': %v", scanInfo.ListingURL, err))
		return false, err
	}
	svc, err := imagescan.NewScanServiceWithMatchers(distCfg, installCfg, imgScanInfo.UseDefaultMatchers)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to initialize image scanner: %s", err))
		return false, err
	}
	defer svc.Close()

	creds := imagescan.RegistryCredentials{
		Authority: imgScanInfo.Authority,
		Username:  imgScanInfo.Username,
		Password:  imgScanInfo.Password,
		Token:     imgScanInfo.Token,
	}

	var vulnerabilityExceptions []string
	var severityExceptions []string
	if imgScanInfo.Exceptions != "" {
		exceptionPolicies, err := GetImageExceptionsFromFile(imgScanInfo.Exceptions)
		if err != nil {
			logger.L().StopError(fmt.Sprintf("Failed to load exceptions from file: %s", imgScanInfo.Exceptions))
			return false, err
		}

		vulnerabilityExceptions, severityExceptions = getUniqueVulnerabilitiesAndSeverities(exceptionPolicies, imgScanInfo.Image)
	}

	imageScanData, err := scanWithRegistryMapping(
		ks.Context(), svc, imgScanInfo.Image, creds,
		scanInfo.RegistryMapping, vulnerabilityExceptions, severityExceptions,
	)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to scan image %s: %s", imgScanInfo.Image, err))
		return false, err
	}

	logger.L().StopSuccess(fmt.Sprintf("Successfully scanned image: %s", imgScanInfo.Image))

	scanInfo.SetScanType(cautils.ScanTypeImage)

	outputPrinters, err := GetOutputPrinters(scanInfo, ks.Context(), "")
	if err != nil {
		return false, err
	}

	uiPrinter := GetUIPrinter(ks.Context(), scanInfo, "")

	resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)

	resultsHandler.ImageScanData = []cautils.ImageScanData{*imageScanData}

	return svc.ExceedsSeverityThreshold(imagescan.ParseSeverity(scanInfo.FailThresholdSeverity), imageScanData.Matches), resultsHandler.HandleResults(ks.Context(), scanInfo)
}
