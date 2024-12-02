package containerscan

import (
	"github.com/armosec/armoapi-go/identifiers"
)

type ElasticContainerVulnerabilityResult struct {
	Designators identifiers.PortalDesignator `json:"designators"`
	Context     []identifiers.ArmoContext    `json:"context"`

	WLID              string    `json:"wlid"`
	ContainerScanID   string    `json:"containersScanID"`
	Layers            []ESLayer `json:"layers"`
	Timestamp         int64     `json:"timestamp"`
	IsFixed           int       `json:"isFixed"`
	IntroducedInLayer string    `json:"layerHash"`
	RelevantLinks     []string  `json:"links"` // Bad SE practice

	Vulnerability `json:",inline"`
}

type ESLayer struct {
	LayerHash       string `json:"layerHash"`
	ParentLayerHash string `json:"parentLayerHash"`
}

type SeverityStats struct {
	Severity                     string `json:"severity,omitempty"`
	TotalCount                   int64  `json:"total"`
	FixAvailableOfTotalCount     int64  `json:"fixedTotal"`
	RelevantCount                int64  `json:"totalRelevant"`
	FixAvailableForRelevantCount int64  `json:"fixedRelevant"`
	RCECount                     int64  `json:"rceTotal"`
	UrgentCount                  int64  `json:"urgent"`
	NeglectedCount               int64  `json:"neglected"`
	HealthStatus                 string `json:"healthStatus"`
}

type ElasticContainerScanSeveritySummary struct {
	Designators identifiers.PortalDesignator `json:"designators"`
	Context     []identifiers.ArmoContext    `json:"context"`

	SeverityStats
	CustomerGUID    string `json:"customerGUID"`
	ContainerScanID string `json:"containersScanID"`
	Timestamp       int64  `json:"timestamp"`
	WLID            string `json:"wlid"`
	ImgTag          string `json:"imageTag"`
	ImgHash         string `json:"imageHash"`
	Cluster         string `json:"cluster"`
	Namespace       string `json:"namespace"`
	ContainerName   string `json:"containerName"`
	Status          string `json:"status"`
	Registry        string `json:"registry"`
	VersionImage    string `json:"versionImage"`
	Version         string `json:"version"`
	DayDate         string `json:"dayDate"`
}

type ElasticContainerScanSummaryResult struct {
	SeverityStats
	Designators identifiers.PortalDesignator `json:"designators"`
	Context     []identifiers.ArmoContext    `json:"context"`

	CustomerGUID    string `json:"customerGUID"`
	ContainerScanID string `json:"containersScanID"`

	Timestamp     int64    `json:"timestamp"`
	WLID          string   `json:"wlid"`
	ImgTag        string   `json:"imageTag"`
	ImgHash       string   `json:"imageHash"`
	Cluster       string   `json:"cluster"`
	Namespace     string   `json:"namespace"`
	ContainerName string   `json:"containerName"`
	PackagesName  []string `json:"packages"`

	ListOfDangerousArtifcats []string `json:"listOfDangerousArtifcats"`

	Status string `json:"status"`

	Registry     string `json:"registry"`
	VersionImage string `json:"versionImage"`

	SeveritiesStats []SeverityStats `json:"severitiesStats"`

	Version string `json:"version"`
}

// Validate checks if the ElasticContainerScanSummaryResult object is valid.
func (summary *ElasticContainerScanSummaryResult) Validate() bool {
	return summary.CustomerGUID != "" && summary.ContainerScanID != "" && (summary.ImgTag != "" || summary.ImgHash != "") && summary.Timestamp > 0
}
