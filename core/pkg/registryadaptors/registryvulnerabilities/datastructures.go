package registryvulnerabilities

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
type Categories struct {
	IsRCE bool `json:"isRce"`
}

type Vulnerability struct {
	Name                     string      `json:"name"`
	RelatedPackageName       string      `json:"packageName"`
	PackageVersion           string      `json:"packageVersion"`
	Link                     string      `json:"link"`
	Description              string      `json:"description"`
	Severity                 string      `json:"severity"`
	Metadata                 interface{} `json:"metadata"`
	Fixes                    []FixedIn   `json:"fixedIn"`
	Relevancy                string      `json:"relevant"` // use the related enum
	UrgentCount              int         `json:"urgent"`
	NeglectedCount           int         `json:"neglected"`
	HealthStatus             string      `json:"healthStatus"`
	Categories               Categories  `json:"categories"`
	NoteName                 string      `json:",omitempty"`
	CreateTime               time.Time   `json:",omitempty"`
	UpdateTime               time.Time   `json:",omitempty"` // Vulnerablity started
	CVSS                     float32     `json:",omitempty"` // other cvss versions are available
	AffectedCPEURI           string      `json:",omitempty"` // Package issue
	AffectedPackage          string      `json:",omitempty"`
	AffectedVersion          string      `json:",omitempty"`
	FixedVersion             string      `json:",omitempty"`
	FixedCPEURI              string      `json:",omitempty"`
	FixedPackege             string      `json:",omitempty"`
	FixAvailablePackage      bool        `json:",omitempty"`
	PackageType              string      `json:",omitempty"`
	EffectiveSeverityPackage string      `json:",omitempty"`
	ShortDescription         string      `json:",omitempty"` // Package issue ends
	LongDescription          string      `json:",omitempty"`
	EffectiveSeverity        string      `json:",omitempty"`
	FixAvailable             bool        `json:",omitempty"`
}

type Attribute struct {
	Cluster       string `json:"cluster"`
	ContainerName string `json:"containerName"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
}

type Designator struct {
	Attributes Attribute `json:"attributes"`
}

type ImageVulnerability struct {
	Name               string     `json:"name"`
	WLID               string     `json:"wlid"`
	Timestamp          int64      `json:"timestamp"`
	Severity           string     `json:"severity"`
	ImageTag           string     `json:"imageTag"`
	Designators        Designator `json:"designators"`
	RelatedPackageName string     `json:"packageName"`
	PackageVersion     string     `json:"packageVersion"`
	Link               string     `json:"link"`
	Description        string     `json:"description"`
	Fixes              []FixedIn  `json:"fixedIn"`
}

type ContainerImageVulnerabilityReport struct {
	ImageID         ContainerImageIdentifier
	Vulnerabilities []Vulnerability
}

type ImageReport struct {
	WLID      string    `json:"WLID"`
	Attribute Attribute `json:"attribute"`
	ImageTag  string    `json:"imageTag"`
}

type ImageCVEreport map[ImageReport][]ImageVulnerability

type ContainerImageInformation struct {
	ImageID ContainerImageIdentifier
	Bom     []string
	//ImageManifest Manifest // will use here Docker package definition
}
