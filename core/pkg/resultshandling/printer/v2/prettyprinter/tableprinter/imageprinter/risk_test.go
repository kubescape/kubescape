package imageprinter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func cveIDs(cves []CVE) []string {
	ids := make([]string, len(cves))
	for i, cve := range cves {
		ids[i] = cve.ID
	}
	return ids
}

func TestSortCVEs(t *testing.T) {
	tests := []struct {
		name string
		cves []CVE
		want []string
	}{
		{
			name: "KEV ranks above higher severity",
			cves: []CVE{
				{ID: "CVE-CRITICAL", Severity: "Critical"},
				{ID: "CVE-MEDIUM-KEV", Severity: "Medium", KEV: true},
				{ID: "CVE-HIGH", Severity: "High"},
			},
			want: []string{"CVE-MEDIUM-KEV", "CVE-CRITICAL", "CVE-HIGH"},
		},
		{
			name: "KEV CVEs are ordered by severity among themselves",
			cves: []CVE{
				{ID: "CVE-LOW-KEV", Severity: "Low", KEV: true},
				{ID: "CVE-CRITICAL-KEV", Severity: "Critical", KEV: true},
			},
			want: []string{"CVE-CRITICAL-KEV", "CVE-LOW-KEV"},
		},
		{
			name: "EPSS orders CVEs of equal severity",
			cves: []CVE{
				{ID: "CVE-A", Severity: "High", EPSS: &EPSS{Score: 0.01}},
				{ID: "CVE-B", Severity: "High", EPSS: &EPSS{Score: 0.9}},
				{ID: "CVE-C", Severity: "High", EPSS: &EPSS{Score: 0.2}},
			},
			want: []string{"CVE-B", "CVE-C", "CVE-A"},
		},
		{
			name: "severity outranks EPSS",
			cves: []CVE{
				{ID: "CVE-MEDIUM", Severity: "Medium", EPSS: &EPSS{Score: 0.97}},
				{ID: "CVE-HIGH", Severity: "High", EPSS: &EPSS{Score: 0.001}},
			},
			want: []string{"CVE-HIGH", "CVE-MEDIUM"},
		},
		{
			name: "a missing EPSS score sorts after a zero score",
			cves: []CVE{
				{ID: "CVE-A", Severity: "High"},
				{ID: "CVE-B", Severity: "High", EPSS: &EPSS{Score: 0}},
			},
			want: []string{"CVE-B", "CVE-A"},
		},
		{
			name: "without KEV or EPSS data the order is severity then ID",
			cves: []CVE{
				{ID: "CVE-Z", Severity: "Low"},
				{ID: "CVE-B", Severity: "Critical"},
				{ID: "CVE-A", Severity: "Critical"},
				{ID: "CVE-M", Severity: "High"},
			},
			want: []string{"CVE-A", "CVE-B", "CVE-M", "CVE-Z"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SortCVEs(tt.cves)
			assert.Equal(t, tt.want, cveIDs(tt.cves))
		})
	}
}

func TestSortCVEsTieBreakers(t *testing.T) {
	cves := []CVE{
		{ID: "CVE-B", Severity: "High", Package: "a"},
		{ID: "CVE-A", Severity: "High", Package: "b", Version: "2", Image: "x"},
		{ID: "CVE-A", Severity: "High", Package: "b", Version: "1", Image: "y"},
		{ID: "CVE-A", Severity: "High", Package: "b", Version: "1", Image: "x"},
		{ID: "CVE-A", Severity: "High", Package: "a"},
	}

	SortCVEs(cves)

	assert.Equal(t, []CVE{
		{ID: "CVE-A", Severity: "High", Package: "a"},
		{ID: "CVE-A", Severity: "High", Package: "b", Version: "1", Image: "x"},
		{ID: "CVE-A", Severity: "High", Package: "b", Version: "1", Image: "y"},
		{ID: "CVE-A", Severity: "High", Package: "b", Version: "2", Image: "x"},
		{ID: "CVE-B", Severity: "High", Package: "a"},
	}, cves)
}

func TestSortedCVEsDoesNotModifyInput(t *testing.T) {
	cves := []CVE{
		{ID: "CVE-LOW", Severity: "Low"},
		{ID: "CVE-KEV", Severity: "Medium", KEV: true},
	}

	got := SortedCVEs(cves)

	assert.Equal(t, []string{"CVE-KEV", "CVE-LOW"}, cveIDs(got))
	assert.Equal(t, []string{"CVE-LOW", "CVE-KEV"}, cveIDs(cves))
}

func TestFormatEPSS(t *testing.T) {
	tests := []struct {
		name            string
		epss            *EPSS
		want            string
		wantProbability string
	}{
		{name: "no score", epss: nil, want: "N/A", wantProbability: "N/A"},
		{name: "rounds to one decimal", epss: &EPSS{Score: 0.63894, Percentile: 0.99215}, want: "63.9% (99th)", wantProbability: "63.9%"},
		{name: "below 0.1 percent", epss: &EPSS{Score: 0.00042, Percentile: 0.12}, want: "< 0.1% (12th)", wantProbability: "< 0.1%"},
		{name: "exactly 0.1 percent", epss: &EPSS{Score: 0.001, Percentile: 0.5}, want: "0.1% (50th)", wantProbability: "0.1%"},
		{name: "percentile does not lose a point to float error", epss: &EPSS{Score: 0.05, Percentile: 0.29}, want: "5.0% (29th)", wantProbability: "5.0%"},
		{name: "1st", epss: &EPSS{Score: 0.002, Percentile: 0.01}, want: "0.2% (1st)", wantProbability: "0.2%"},
		{name: "22nd", epss: &EPSS{Score: 0.002, Percentile: 0.22}, want: "0.2% (22nd)", wantProbability: "0.2%"},
		{name: "33rd", epss: &EPSS{Score: 0.002, Percentile: 0.33}, want: "0.2% (33rd)", wantProbability: "0.2%"},
		{name: "11th to 13th", epss: &EPSS{Score: 0.002, Percentile: 0.13}, want: "0.2% (13th)", wantProbability: "0.2%"},
		{name: "0th", epss: &EPSS{Score: 0, Percentile: 0}, want: "< 0.1% (0th)", wantProbability: "< 0.1%"},
		{name: "100th", epss: &EPSS{Score: 0.97, Percentile: 1}, want: "97.0% (100th)", wantProbability: "97.0%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FormatEPSS(tt.epss))
			assert.Equal(t, tt.wantProbability, FormatEPSSProbability(tt.epss))
		})
	}
}

func TestFormatKEV(t *testing.T) {
	assert.Equal(t, "yes", FormatKEV(true))
	assert.Equal(t, "", FormatKEV(false))
}
