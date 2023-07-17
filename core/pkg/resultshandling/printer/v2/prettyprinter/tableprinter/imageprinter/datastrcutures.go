package imageprinter

type ImageScanSummary struct {
	MapsSeverityToSummary map[string]*SeveritySummary
	CVEs                  []CVE
	PackageScores         map[string]*Package
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

type Package struct {
	Version string
	Score   int
}
