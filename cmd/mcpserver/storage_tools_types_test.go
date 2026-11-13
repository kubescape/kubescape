package mcpserver

import "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

// The answers of storage's read tools, as the tests here decode them.

// vulnerabilityEntry is one match of a CVE against a package. The package is
// part of the entry: the same CVE often matches several packages, and without
// it those entries are indistinguishable.
type vulnerabilityEntry struct {
	ID          string             `json:"id"`
	Severity    string             `json:"severity"`
	Package     string             `json:"package"`
	Version     string             `json:"version"`
	PackageType string             `json:"package_type"`
	PURL        string             `json:"purl,omitempty"`
	Fix         v1beta1.Fix        `json:"fix"`
	Description string             `json:"description,omitempty"`
	Cvss        []v1beta1.Cvss     `json:"cvss,omitempty"`
	URLs        []string           `json:"urls,omitempty"`
	Advisories  []v1beta1.Advisory `json:"advisories,omitempty"`
	DataSource  string             `json:"data_source,omitempty"`
}

type vulnerabilityListResponse struct {
	Total           int                  `json:"total"`
	Returned        int                  `json:"returned"`
	Truncated       bool                 `json:"truncated"`
	NextOffset      *int                 `json:"next_offset,omitempty"`
	Vulnerabilities []vulnerabilityEntry `json:"vulnerabilities"`
}

// sbomEntry describes one stored SBOM without its content.
type sbomEntry struct {
	Namespace string `json:"namespace"`
	SBOMName  string `json:"sbom_name"`
	ImageID   string `json:"image_id,omitempty"`
	ImageTag  string `json:"image_tag,omitempty"`
	Status    string `json:"status,omitempty"`
}

type sbomListResponse struct {
	SBOMs    []sbomEntry `json:"sboms"`
	Continue string      `json:"continue,omitempty"`
}

// sbomPackageEntry is one package of an SBOM. Locations, CPEs and the
// cataloger metadata are left out: they make up most of the document and an
// agent rarely needs them to answer "is this package in the image".
type sbomPackageEntry struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"`
	Language string   `json:"language,omitempty"`
	PURL     string   `json:"purl,omitempty"`
	Licenses []string `json:"licenses"`
}

type sbomPackageListResponse struct {
	SBOMName string `json:"sbom_name"`
	// Status is the SBOM's kubescape.io/status annotation. An SBOM that was
	// too large to store has a status and no packages, which is not the same
	// as an image with no packages.
	Status     string             `json:"status,omitempty"`
	Distro     string             `json:"distro,omitempty"`
	Total      int                `json:"total"`
	Returned   int                `json:"returned"`
	Truncated  bool               `json:"truncated"`
	NextOffset *int               `json:"next_offset,omitempty"`
	Packages   []sbomPackageEntry `json:"packages"`
}
