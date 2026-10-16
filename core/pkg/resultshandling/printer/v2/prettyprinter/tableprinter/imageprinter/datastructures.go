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
	// KEV is true when the vulnerability is on the CISA Known Exploited
	// Vulnerabilities catalog.
	KEV bool
	// EPSS is nil when the vulnerability database has no EPSS score for it.
	EPSS *EPSS
}

// EPSS is a FIRST Exploit Prediction Scoring System score.
type EPSS struct {
	// Score is the probability, from 0 to 1, of exploitation activity in the
	// next 30 days.
	Score float64
	// Percentile is the share of all scored vulnerabilities, from 0 to 1,
	// with an equal or lower score.
	Percentile float64
}

type PackageScore struct {
	Name                    string
	Version                 string
	Score                   int
	MapSeverityToCVEsNumber map[string]int
}
