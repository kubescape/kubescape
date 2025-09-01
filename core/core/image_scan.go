package core

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

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

// Loads excpetion policies from exceptions json object.
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
	canonicalImageName, err := cautils.NormalizeImageName(imgName)
	if err != nil {
		return Attributes{}, err
	}

	tokens := strings.Split(canonicalImageName, "/")
	registry := tokens[0]
	organization := tokens[1]

	imageNameAndTag := strings.Split(tokens[2], ":")
	imageName := imageNameAndTag[0]

	// Intialize the image tag with default value
	imageTag := "latest"
	if len(imageNameAndTag) > 1 {
		imageTag = imageNameAndTag[1]
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
				// Add to slice directly
				vulnerabilityUppercase := strings.ToUpper(vulnerability)
				uniqueVulns[vulnerabilityUppercase] = append(uniqueVulns[vulnerabilityUppercase], vulnerability)
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

func (ks *Kubescape) ScanImage(imgScanInfo *ksmetav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	logger.L().Start(fmt.Sprintf("Scanning image %s...", imgScanInfo.Image))

	dbCfg, _ := imagescan.NewDefaultDBConfig()
	svc, err := imagescan.NewScanService(dbCfg)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to initialize image scanner: %s", err))
		return false, err
	}
	defer svc.Close()

	creds := imagescan.RegistryCredentials{
		Username: imgScanInfo.Username,
		Password: imgScanInfo.Password,
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

	scanResults, err := svc.Scan(ks.Context(), imgScanInfo.Image, creds, vulnerabilityExceptions, severityExceptions)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to scan image: %s", imgScanInfo.Image))
		return false, err
	}

	logger.L().StopSuccess(fmt.Sprintf("Successfully scanned image: %s", imgScanInfo.Image))

	scanInfo.SetScanType(cautils.ScanTypeImage)

	outputPrinters := GetOutputPrinters(scanInfo, ks.Context(), "")

	uiPrinter := GetUIPrinter(ks.Context(), scanInfo, "")

	resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)

	resultsHandler.ImageScanData = []cautils.ImageScanData{
		{
			PresenterConfig: scanResults,
			Image:           imgScanInfo.Image,
		},
	}

	return imagescan.ExceedsSeverityThreshold(scanResults, imagescan.ParseSeverity(scanInfo.FailThresholdSeverity)), resultsHandler.HandleResults(ks.Context(), scanInfo)
}
