package imageprinter

import (
	"cmp"
	"fmt"
	"math"
	"slices"

	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
)

// CompareCVEs orders CVEs by exploitation risk: those on the CISA KEV catalog
// first, then by severity, then by EPSS score, highest first. A CVE without an
// EPSS score sorts after one with any score. Remaining ties fall back to ID,
// package, version and image so the order is deterministic.
func CompareCVEs(a, b CVE) int {
	if a.KEV != b.KEV {
		if a.KEV {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(utils.ImageSeverityToInt(b.Severity), utils.ImageSeverityToInt(a.Severity)); c != 0 {
		return c
	}
	if c := cmp.Compare(epssSortKey(b.EPSS), epssSortKey(a.EPSS)); c != 0 {
		return c
	}
	return cmp.Or(
		cmp.Compare(a.ID, b.ID),
		cmp.Compare(a.Package, b.Package),
		cmp.Compare(a.Version, b.Version),
		cmp.Compare(a.Image, b.Image),
	)
}

// SortCVEs sorts cves in place with CompareCVEs.
func SortCVEs(cves []CVE) {
	slices.SortStableFunc(cves, CompareCVEs)
}

// SortedCVEs returns a copy of cves sorted with CompareCVEs.
func SortedCVEs(cves []CVE) []CVE {
	out := slices.Clone(cves)
	SortCVEs(out)
	return out
}

func epssSortKey(e *EPSS) float64 {
	if e == nil {
		return -1
	}
	return e.Score
}

// FormatEPSS renders an EPSS score the way grype's table does, as the
// probability and its percentile, e.g. "63.9% (99th)". It returns "N/A" when
// there is no score.
func FormatEPSS(e *EPSS) string {
	if e == nil {
		return "N/A"
	}
	// The epsilon keeps a percentile like 0.29 from truncating to 28, since
	// 0.29*100 is 28.999999999999996 in floating point.
	percentile := int(math.Floor(e.Percentile*100 + 1e-9))
	return fmt.Sprintf("%s (%s)", FormatEPSSProbability(e), ordinal(percentile))
}

// FormatEPSSProbability renders only the probability of an EPSS score, e.g.
// "63.9%", for layouts too narrow for the percentile. It returns "N/A" when
// there is no score.
func FormatEPSSProbability(e *EPSS) string {
	if e == nil {
		return "N/A"
	}
	probability := e.Score * 100
	if probability < 0.1 {
		return "< 0.1%"
	}
	return fmt.Sprintf("%.1f%%", probability)
}

// FormatKEV renders the KEV marker: "yes" for a CVE on the CISA KEV catalog,
// otherwise an empty string.
func FormatKEV(kev bool) string {
	if kev {
		return "yes"
	}
	return ""
}

func ordinal(n int) string {
	if n%100 >= 11 && n%100 <= 13 {
		return fmt.Sprintf("%dth", n)
	}
	switch n % 10 {
	case 1:
		return fmt.Sprintf("%dst", n)
	case 2:
		return fmt.Sprintf("%dnd", n)
	case 3:
		return fmt.Sprintf("%drd", n)
	default:
		return fmt.Sprintf("%dth", n)
	}
}
