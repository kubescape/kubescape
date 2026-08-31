package imageprinter

import "time"

type ImageScanSummary struct {
	MapsSeverityToSummary map[string]*SeveritySummary
	CVEs                  []CVE
	PackageScores         map[string]*PackageScore // map of package name to package score
	Images                []string
	// VulnDBBuilt is the vulnerability DB build timestamp, surfaced so users can
	// judge data freshness. Nil when unknown.
	VulnDBBuilt *time.Time
}

type SeveritySummary struct {
	NumberOfCVEs        int
	NumberOfFixableCVEs int
}

type CVE struct {
	Severity         string
	ID               string
	Package          string
	Version          string
	FixVersions      []string
	FixedState       string
	Image            string
	VexStatus        string
	VexJustification string
}

type PackageScore struct {
	Name                    string
	Version                 string
	Score                   int
	MapSeverityToCVEsNumber map[string]int
}
