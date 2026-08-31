// Package vulnexposure joins two capabilities that otherwise never speak to
// each other in this repo: image vulnerability data (a workload's known
// CVEs, sourced from an already-running in-cluster scanner via
// VulnerabilityManifest objects) and NetworkPolicy ingress exposure (core/pkg
// /networkpolicy). Neither, on its own, answers the question that actually
// matters for prioritization: a critical, fixable CVE on a workload wide
// open to the whole cluster is a materially different risk than the same CVE
// on a workload no NetworkPolicy lets anything reach.
package vulnexposure

import (
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/networkpolicy"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// Severity is a coarse, ordered vulnerability severity, so callers can
// filter/sort by a threshold without depending on grype's exact severity
// string spelling or casing.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityNegligible
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "Critical"
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityLow:
		return "Low"
	case SeverityNegligible:
		return "Negligible"
	default:
		return "Unknown"
	}
}

// ParseSeverity converts a grype-style severity string to Severity,
// case-insensitively. An unrecognized string (including empty) is
// SeverityUnknown, not an error: a manifest with a severity grype has not
// classified should not be silently dropped by a naive string comparison,
// but it also should not be promoted above a real severity by accident, so
// it sorts below every known level.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "negligible":
		return SeverityNegligible
	default:
		return SeverityUnknown
	}
}

// Workload identifies one workload a VulnerabilityManifest was produced for.
type Workload struct {
	Namespace string
	Kind      string
	Name      string
}

// Finding is one (workload, vulnerability) pair worth surfacing, joined with
// how exposed that workload's ingress is.
type Finding struct {
	Workload      Workload
	Vulnerability storagev1beta1.VulnerabilityMetadata
	// FixAvailable is true when grype reports a fixed version exists --
	// worth carrying alongside severity, since a fixable critical CVE on an
	// exposed workload is the most actionable class of finding this
	// produces.
	FixAvailable bool
	Exposure     networkpolicy.Exposure
}

// exposureRank orders Finding.Exposure.Level the same way
// networkpolicy.ExposureLevel's own int values already do (higher is more
// exposed), kept as a named function so Correlate's sort reads by intent
// rather than by the underlying type's representation.
func exposureRank(e networkpolicy.Exposure) int {
	return int(e.Level)
}

// Correlate joins each workload's known vulnerabilities (at or above
// minSeverity) with its ingress exposure. A workload with vulnerabilities
// but no entry in endpoints is skipped, not guessed at: this package never
// assumes an exposure level for a workload it was not given a resolved
// Endpoint for (e.g. because its kind could not be mapped to a concrete pod
// template, or the live Get failed) -- see the "skipped" return for exactly
// which workloads that happened to.
//
// Results are sorted most-actionable first: widest exposure, then highest
// severity, then a stable ID/name tiebreak, so a caller displaying only the
// top N never has to sort them itself.
func Correlate(idx *networkpolicy.Index, endpoints map[Workload]networkpolicy.Endpoint, vulnerabilitiesByWorkload map[Workload][]storagev1beta1.Vulnerability, minSeverity Severity) (findings []Finding, skipped []Workload) {
	for workload, vulns := range vulnerabilitiesByWorkload {
		ep, ok := endpoints[workload]
		if !ok {
			skipped = append(skipped, workload)
			continue
		}

		exposure := idx.IngressExposure(ep)
		for _, v := range vulns {
			if ParseSeverity(v.Severity) < minSeverity {
				continue
			}
			findings = append(findings, Finding{
				Workload:      workload,
				Vulnerability: v.VulnerabilityMetadata,
				FixAvailable:  len(v.Fix.Versions) > 0 && v.Fix.State == "fixed",
				Exposure:      exposure,
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := exposureRank(a.Exposure), exposureRank(b.Exposure); ra != rb {
			return ra > rb
		}
		if sa, sb := ParseSeverity(a.Vulnerability.Severity), ParseSeverity(b.Vulnerability.Severity); sa != sb {
			return sa > sb
		}
		if a.Workload != b.Workload {
			if a.Workload.Namespace != b.Workload.Namespace {
				return a.Workload.Namespace < b.Workload.Namespace
			}
			if a.Workload.Kind != b.Workload.Kind {
				return a.Workload.Kind < b.Workload.Kind
			}
			return a.Workload.Name < b.Workload.Name
		}
		return a.Vulnerability.ID < b.Vulnerability.ID
	})
	sort.Slice(skipped, func(i, j int) bool {
		if skipped[i].Namespace != skipped[j].Namespace {
			return skipped[i].Namespace < skipped[j].Namespace
		}
		if skipped[i].Kind != skipped[j].Kind {
			return skipped[i].Kind < skipped[j].Kind
		}
		return skipped[i].Name < skipped[j].Name
	})

	return findings, skipped
}
