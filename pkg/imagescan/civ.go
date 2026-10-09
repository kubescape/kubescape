package imagescan

import (
	"context"
	"time"

	"github.com/docker/distribution/manifest/schema2"
)

// ContainerImageIdentifier uniquely identifies a container image
type ContainerImageIdentifier struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Hash       string `json:"hash"`
}

// ScanStatus represents the outcome of a vulnerability scan attempt
type ScanStatus string

const (
	// ScanStatusScanned indicates the scan completed successfully
	ScanStatusScanned ScanStatus = "scanned"
	// ScanStatusQueued indicates the scan is pending or in-progress
	ScanStatusQueued ScanStatus = "queued"
	// ScanStatusUnsupported indicates the image format is not supported for scanning
	// (e.g., scratch, static binaries, distroless without OS packages)
	ScanStatusUnsupported ScanStatus = "unsupported"
	// ScanStatusFailed indicates the scan was attempted but failed
	ScanStatusFailed ScanStatus = "failed"
	// ScanStatusUnknown indicates the scan status could not be determined
	ScanStatusUnknown ScanStatus = "unknown"
)

// IsTerminal returns true if the scan status represents a final state
// (i.e., it won't change with time). Queued scans are non-terminal.
func (s ScanStatus) IsTerminal() bool {
	return s == ScanStatusScanned || s == ScanStatusUnsupported || s == ScanStatusFailed
}

// ContainerImageScanStatus represents the current state of vulnerability scanning for an image
type ContainerImageScanStatus struct {
	ImageID         ContainerImageIdentifier `json:"imageID"`
	IsScanAvailable bool                     `json:"isScanAvailable"`
	IsBomAvailable  bool                     `json:"isBomAvailable"`
	LastScanDate    time.Time                `json:"lastScanDate"`
	Status          ScanStatus               `json:"status,omitempty"`
}

// Vulnerability represents a single container vulnerability
type Vulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Links       []string `json:"links,omitempty"`
}

// ContainerImageVulnerabilityReport contains the vulnerabilities found in an image
type ContainerImageVulnerabilityReport struct {
	ImageID         ContainerImageIdentifier `json:"imageID"`
	Vulnerabilities []Vulnerability          `json:"vulnerabilities,omitempty"`
	Status          ScanStatus               `json:"status,omitempty"`
}

// ContainerImageInformation contains the metadata and bill of materials for an image
type ContainerImageInformation struct {
	ImageID       ContainerImageIdentifier `json:"imageID"`
	Bom           []string                 `json:"bom"`
	ImageManifest schema2.Manifest         `json:"imageManifest"`
}

// IContainerImageVulnerabilityAdaptor defines the unified interface for interacting with
// external container image registries and vulnerability scanners (e.g. Harbor, ECR).
type IContainerImageVulnerabilityAdaptor interface {
	// Login authenticates with the external provider.
	// Credentials use the standard RegistryCredentials struct for compile-checked auth.
	Login(ctx context.Context, registry string, credentials RegistryCredentials) error

	// DescribeAdaptor provides a string description of the adaptor for help purposes.
	DescribeAdaptor() string

	// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
	GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error)

	// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
	GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error)

	// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
	GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error)

	// Destroy cleans up any persistent resources (like connections) used by the adaptor.
	Destroy() error
}
