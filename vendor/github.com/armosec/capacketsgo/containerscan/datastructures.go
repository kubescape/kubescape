package containerscan

import (
	"crypto/sha256"
	"fmt"
)

//!!!!!!!!!!!!EVERY CHANGE IN THESE STRUCTURES => CHANGE gojayunmarshaller ASWELL!!!!!!!!!!!!!!!!!!!!!!!!

// ScanResultReport - the report given from scanner to event receiver
type ScanResultReport struct {
	CustomerGUID             string     `json:"customerGUID"`
	ImgTag                   string     `json:"imageTag",omitempty`
	ImgHash                  string     `json:"imageHash"`
	WLID                     string     `json:"wlid"`
	ContainerName            string     `json:"containerName"`
	Timestamp                int64      `json:"timestamp"`
	Layers                   LayersList `json:"layers"`
	ListOfDangerousArtifcats []string   `json:"listOfDangerousArtifcats"`
}

// ScanResultLayer - represents a single layer from container scan result
type ScanResultLayer struct {
	LayerHash       string              `json:"layerHash"`
	ParentLayerHash string              `json:"parentLayerHash"`
	Vulnerabilities VulnerabilitiesList `json:"vulnerabilities"`
	Packages        LinuxPkgs           `json:"packageToFile"`
}

// Vulnerability - a vul object
type Vulnerability struct {
	Name               string      `json:"name"`
	ImgHash            string      `json:"imageHash"`
	ImgTag             string      `json:"imageTag",omitempty`
	RelatedPackageName string      `json:"packageName"`
	PackageVersion     string      `json:"packageVersion"`
	Link               string      `json:"link"`
	Description        string      `json:"description"`
	Severity           string      `json:"severity"`
	Metadata           interface{} `json:"metadata",omitempty`
	Fixes              VulFixes    `json:"fixedIn",omitempty`
	Relevancy          string      `json:"relevant"` // use the related enum
}

// FixedIn when and which pkg was fixed (which version as well)
type FixedIn struct {
	Name    string `json:"name"`
	ImgTag  string `json:"imageTag"`
	Version string `json:"version"`
}

// LinuxPackage- Linux package representation
type LinuxPackage struct {
	PackageName    string   `json:"packageName"`
	Files          PkgFiles `json:"files"`
	PackageVersion string   `json:"version"`
}

// PackageFile - s.e
type PackageFile struct {
	Filename string `json:"name"`
}

// types to provide unmarshalling:

//VulnerabilitiesList -s.e
type LayersList []ScanResultLayer

//VulnerabilitiesList -s.e
type VulnerabilitiesList []Vulnerability

//LinuxPkgs - slice of linux pkgs
type LinuxPkgs []LinuxPackage

//VulFixes - information bout when/how this vul was fixed
type VulFixes []FixedIn

//PkgFiles - slice of files belong to specific pkg
type PkgFiles []PackageFile

func (v *ScanResultReport) AsSha256() string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", *v)))

	return fmt.Sprintf("%x", h.Sum(nil))
}

const (
	//defines Relevancy as enum-like
	Unknown   = "Unknown"
	Relevant  = "Relevant"
	Irelevant = "Irelevant"
	NoSP      = "No signature profile to compare"

	//Clair Severities
	UnknownSeverity    = "Unknown"
	NegligibleSeverity = "Negligible"
	LowSeverity        = "Low"
	MediumSeverity     = "Medium"
	HighSeverity       = "High"
	CriticalSeverity   = "Critical"

	ContainerScanRedisPrefix = "_containerscan"
)

func CalculateFixed(Fixes []FixedIn) int {
	for _, fix := range Fixes {
		if fix.Version != "None" {
			return 1
		}
	}
	return 0
}
