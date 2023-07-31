package imageprinter

type ImageScanSummary struct {
	MapsSeverityToSummary map[string]*SeveritySummary
	CVEs                  []CVE
	PackageScores         map[string]*PackageScore // map of package name to package score
	Images                []string
}

type SeveritySummary struct {
	NumberOfCVEs        int
	NumberOfFixableCVEs int
}

type CVE struct {
	Severity    string
	ID          string
	Package     string
	Version     string
	FixVersions []string
	FixedState  string
}

type PackageScore struct {
	Name                    string
	Version                 string
	Score                   int
	MapSeverityToCVEsNumber map[string]int
}
