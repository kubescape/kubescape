package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
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

func getUniqueVulnerabilities(policies []VulnerabilitiesIgnorePolicy) []string {
	// Create a map to store unique vulnerabilities (case-insensitive)
	uniqueVulns := make(map[string]bool)

	// Iterate over each policy
	for _, policy := range policies {
		// Iterate over each vulnerability in the policy
		for _, vuln := range policy.Vulnerabilities {
			// Convert to uppercase for case-insensitive comparison
			vulnLower := strings.ToUpper(vuln)

			// Add the vulnerability to the map (only if it's not already present)
			uniqueVulns[vulnLower] = true
		}
	}

	// Convert the map keys (unique vulnerabilities) to a slice
	uniqueVulnsList := make([]string, 0, len(uniqueVulns))
	for vuln := range uniqueVulns {
		uniqueVulnsList = append(uniqueVulnsList, vuln)
	}

	return uniqueVulnsList
}

func (ks *Kubescape) ScanImage(ctx context.Context, imgScanInfo *ksmetav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (*models.PresenterConfig, error) {
	logger.L().Start(fmt.Sprintf("Scanning image %s...", imgScanInfo.Image))

	dbCfg, _ := imagescan.NewDefaultDBConfig()
	svc := imagescan.NewScanService(dbCfg)

	creds := imagescan.RegistryCredentials{
		Username: imgScanInfo.Username,
		Password: imgScanInfo.Password,
	}

	var vulnerabilityExceptions []string
	if imgScanInfo.Exceptions != "" {
		exceptionPolicies, err := GetImageExceptionsFromFile(imgScanInfo.Exceptions)
		if err != nil {
			logger.L().StopError(fmt.Sprintf("Failed to load exceptions from file: %s", imgScanInfo.Exceptions))
			return nil, err
		}

		vulnerabilityExceptions = getUniqueVulnerabilities(exceptionPolicies)
	}

	scanResults, err := svc.Scan(ctx, imgScanInfo.Image, creds, vulnerabilityExceptions)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to scan image: %s", imgScanInfo.Image))
		return nil, err
	}

	logger.L().StopSuccess(fmt.Sprintf("Successfully scanned image: %s", imgScanInfo.Image))

	scanInfo.SetScanType(cautils.ScanTypeImage)

	outputPrinters := GetOutputPrinters(scanInfo, ctx, "")

	uiPrinter := GetUIPrinter(ctx, scanInfo, "")

	resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)

	resultsHandler.ImageScanData = []cautils.ImageScanData{
		{
			PresenterConfig: scanResults,
			Image:           imgScanInfo.Image,
		},
	}

	return scanResults, resultsHandler.HandleResults(ctx)
}
