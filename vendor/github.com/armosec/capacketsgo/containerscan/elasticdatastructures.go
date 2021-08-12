package containerscan

type ElasticContainerVulnerabilityResult struct {
	WLID              string    `json:"wlid"`
	ContainerScanID   string    `json:"containersScanID"`
	Layers            []ESLayer `json:"layers"`
	Timestamp         int64     `json:"timestamp"`
	IsFixed           int       `json:"isFixed"`
	IntroducedInLayer string    `json:LayerHash`
	RelevantLinks     []string  `json:"links"` // shitty SE practice
	//

	Vulnerability `json:",inline"`
}

type ESLayer struct {
	LayerHash       string `json:"layerHash"`
	ParentLayerHash string `json:"parentLayerHash"`
}
type ElasticContainerScanSummaryResult struct {
	CustomerGUID    string `json:"customerGUID"`
	ContainerScanID string `json:"containersScanID"`

	Timestamp     int64    `json:"timestamp"`
	WLID          string   `json:"wlid"`
	ImgTag        string   `json:"imageTag",omitempty`
	ImgHash       string   `json:"imageHash"`
	Cluster       string   `json:"cluster"`
	Namespace     string   `json:"namespace"`
	ContainerName string   `json:"containerName"`
	PackagesName  []string `json:"packages"`

	Severity                 []string `json:"severities"`
	Relevancy                []string `json:"relevancies"`
	FixAvailble              []string `json:"fixes"`
	ListOfDangerousArtifcats []string `json:"listOfDangerousArtifcats"`

	SeveritiesSum  []RelevanciesSum `json:"severitiesSum"`
	RelevanciesSum []RelevanciesSum `json:"relevanciesSum"`
	FixAvailbleSum []RelevanciesSum `json:"fixAvailbleSum"`

	Status string `json:"status"`

	Registry     string `json:"registry"`
	VersionImage string `json:"versionImage"`

	RCESummary              map[string]int64 `json:"RCE,omitempty"`
	NumOfUnknownSeverity    int64            `json:"numOfUnknownSeverity"`
	NumOfNegligibleSeverity int64            `json:"numOfNegligibleSeverity"`
	NumOfLowSeverity        int64            `json:"numOfLowSeverity"`
	NumOfMediumSeverity     int64            `json:"numOfMeduiumSeverity"`
	NumOfHighSeverity       int64            `json:"numOfHighSeverity"`
	NumOfCriticalSeverity   int64            `json:"numOfCriticalSeverity"`

	NumOfRelevantUnknownSeverity    int64 `json:"numOfRelevantUnknownSeverity"`
	NumOfRelevantNegligibleSeverity int64 `json:"numOfRelevantNegligibleSeverity"`
	NumOfRelevantLowSeverity        int64 `json:"numOfRelevantLowSeverity"`
	NumOfRelevantMediumSeverity     int64 `json:"numOfRelevantMediumSeverity"`
	NumOfRelevantHighSeverity       int64 `json:"numOfHighRelevantSeverity"`
	NumOfRelevantCriticalSeverity   int64 `json:"numOfRelevantCriticalSeverity"`

	NumOfFixAvailableUnknownSeverity    int64 `json:"numOfFixAvailableUnknownSeverity"`
	NumOfFixAvailableNegligibleSeverity int64 `json:"numOfFixAvailableNegligibleSeverity"`
	NumOfFixAvailableLowSeverity        int64 `json:"numOfFixAvailableLowSeverity"`
	NumOfFixAvailableMediumSeverity     int64 `json:"numOfFixAvailableMediumSeverity"`
	NumOfFixAvailableHighSeverity       int64 `json:"numOfFixAvailableHighSeverity"`
	NumOfFixAvailableCriticalSeverity   int64 `json:"numOfFixAvailableCriticalSeverity"`

	NumOfRelevantIssues  int64 `json:"numOfRelevantIssues"`
	NumOfIrelevantIssues int64 `json:"numOfIrelevantIssues"`
	NumOfUnknownIssues   int64 `json:"numOfUnknownIssues"`

	NumOfLeakedSecrets int64  `json:"numOfLeakedSecrets"`
	Version            string `json:"version"`

	History []ContainerScanHistoryEntry `json:"history",omitempty`
}

type RelevanciesSum struct {
	Relevancy string `json:"relevancy"`
	Sum       int64  `json:"sum"`
}

type ContainerScanHistoryEntry struct {
	ContainerScanID string `json:"containerScanID"`
	Timestamp       int64  `json:"timestamp"`
}

func (summary *ElasticContainerScanSummaryResult) Validate() bool {
	return summary.CustomerGUID != "" && summary.ContainerScanID != "" && (summary.ImgTag != "" || summary.ImgHash != "") && summary.Timestamp > 0
}
