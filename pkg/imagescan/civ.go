package imagescan

import "time"

// ContainerImageIdentifier uniquely identifies a container image
type ContainerImageIdentifier struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Hash       string `json:"hash"`
}

// ContainerImageScanStatus represents the current state of vulnerability scanning for an image
type ContainerImageScanStatus struct {
	ImageID         ContainerImageIdentifier `json:"imageID"`
	IsScanAvailable bool                     `json:"isScanAvailable"`
	IsBomAvailable  bool                     `json:"isBomAvailable"`
	LastScanDate    time.Time                `json:"lastScanDate"`
}

// ContainerImageVulnerabilityReport contains the vulnerabilities found in an image
type ContainerImageVulnerabilityReport struct {
	ImageID         ContainerImageIdentifier `json:"imageID"`
	Vulnerabilities []any                    `json:"vulnerabilities,omitempty"` // TBD: Map to appropriate vulnerability struct
}

// ContainerImageInformation contains the metadata and bill of materials for an image
type ContainerImageInformation struct {
	ImageID       ContainerImageIdentifier `json:"imageID"`
	Bom           []string                 `json:"bom"`
	ImageManifest any                      `json:"imageManifest"` // Docker package definition (e.g. github.com/docker/distribution/manifest/schema2.Manifest)
}

// IContainerImageVulnerabilityAdaptor defines the unified interface for interacting with
// external container image registries and vulnerability scanners (e.g. Harbor, ECR).
type IContainerImageVulnerabilityAdaptor interface {
	// Login authenticates with the external provider.
	// Credentials are coming from user input (CLI or configuration file) and they are abstracted at string to string map level
	// so an example use would be like registry: "simpledockerregistry:80" and credentials like {"username":"joedoe","password":"abcd1234"}
	Login(registry string, credentials map[string]string) error

	// DescribeAdaptor provides a string description of the adaptor for help purposes.
	DescribeAdaptor() string

	// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
	GetImagesScanStatus(imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error)

	// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
	GetImagesVulnerabilities(imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error)

	// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
	GetImagesInformation(imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error)
}
