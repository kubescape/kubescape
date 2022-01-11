package containerimages

import (
	"time"
)

type ContainerImageIdentifier struct {
	Registry   string
	Repository string
	Tag        string
	Hash       string
}

type ContainerImageScanStatus struct {
	ImageID         ContainerImageIdentifier
	IsScanAvailable bool
	IsBomAvailable  bool
	LastScanDate    time.Time
}

type FixedIn struct {
	Name    string `json:"name"`
	ImgTag  string `json:"imageTag"`
	Version string `json:"version"`
}
type Vulnerability struct {
	Name               string      `json:"name"`
	RelatedPackageName string      `json:"packageName"`
	PackageVersion     string      `json:"packageVersion"`
	Link               string      `json:"link"`
	Description        string      `json:"description"`
	Severity           string      `json:"severity"`
	Metadata           interface{} `json:"metadata"`
	Fixes              []FixedIn   `json:"fixedIn"`
	Relevancy          string      `json:"relevant"` // use the related enum
	UrgentCount        int         `json:"urgent"`
	NeglectedCount     int         `json:"neglected"`
	HealthStatus       string      `json:"healthStatus"`
}

type ContainerImageVulnerabilityReport struct {
	ImageID         ContainerImageIdentifier
	Vulnerabilities []Vulnerability
}

type ContainerImageInformation struct {
	ImageID ContainerImageIdentifier
	Bom     []string
	//ImageManifest Manifest // will use here Docker package definition
}

type IContainerImageVulnerabilityAdaptor interface {
	// Credentials are coming from user input (CLI or configuration file) and they are abstracted at string to string map level
	// so and example use would be like registry: "simpledockerregistry:80" and credentials like {"username":"joedoe","password":"abcd1234"}
	Login(registry string, credentials map[string]string) error

	// For "help" purposes
	DescribeAdaptor() string

	GetImagesScanStatus(imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error)

	GetImagesVulnerabilties(imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error)

	GetImagesInformation(imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error)
}
