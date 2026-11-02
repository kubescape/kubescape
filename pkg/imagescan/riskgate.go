package imagescan

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

// RiskGates are the exploitability gates that fail an image scan
// independently of the severity threshold. The zero value disables both.
type RiskGates struct {
	// FailOnKEV fails on any match listed in the CISA Known Exploited
	// Vulnerabilities catalog.
	FailOnKEV bool
	// EPSSThreshold fails on any match whose EPSS score is at or above it.
	// Zero disables the gate.
	EPSSThreshold float64
}

// Enabled reports whether any exploitability gate is set.
func (g RiskGates) Enabled() bool {
	return g.FailOnKEV || g.EPSSThreshold > 0
}

// RiskGateResult counts, across one or more images, the matches that tripped
// each exploitability gate.
type RiskGateResult struct {
	KEV  int // matches listed in CISA KEV
	EPSS int // matches whose EPSS score is at or above the threshold
	// Indeterminate counts matches whose vulnerability metadata could not be
	// resolved, so neither gate can clear them. Like an unknown severity
	// under the severity threshold, they fail the scan.
	Indeterminate int
	// EPSSChecked and EPSSScored count the matches checked against the EPSS
	// gate and those of them that carried a score. A match without a score
	// cannot trip the gate.
	EPSSChecked int
	EPSSScored  int
}

// Add accumulates another image's result into r.
func (r *RiskGateResult) Add(other RiskGateResult) {
	r.KEV += other.KEV
	r.EPSS += other.EPSS
	r.Indeterminate += other.Indeterminate
	r.EPSSChecked += other.EPSSChecked
	r.EPSSScored += other.EPSSScored
}

// EvaluateRiskGates checks matches against the exploitability gates. Matches
// waived by image exceptions are already absent from matches, so a severity
// exception waives a KEV or high-EPSS finding the same way it waives a
// severity breach. With onlyFixable, only matches grype reports as fixed are
// counted, mirroring ExceedsSeverityThreshold, including its fail-closed
// handling of matches whose metadata cannot be resolved.
func EvaluateRiskGates(gates RiskGates, matches match.Matches, vp vulnerability.Provider, onlyFixable bool) RiskGateResult {
	var result RiskGateResult
	if !gates.Enabled() {
		return result
	}
	// Drain matches.Enumerate() fully: it is fed by a goroutine over an
	// unbuffered channel, so an early return would leak the producer.
	for m := range matches.Enumerate() {
		metadata := exploitMetadata(m, vp)
		if metadata == nil {
			if onlyFixable && IsDefinitivelyUnfixable(m.Vulnerability.Fix.State) {
				continue
			}
			result.Indeterminate++
			continue
		}
		if onlyFixable && m.Vulnerability.Fix.State != vulnerability.FixStateFixed {
			continue
		}
		if gates.FailOnKEV && len(metadata.KnownExploited) > 0 {
			result.KEV++
		}
		if gates.EPSSThreshold > 0 {
			result.EPSSChecked++
			if score, ok := HighestEPSS(metadata.EPSS); ok {
				result.EPSSScored++
				if score >= gates.EPSSThreshold {
					result.EPSS++
				}
			}
		}
	}
	return result
}

// HighestEPSS returns the highest of a match's EPSS scores. Grype attaches
// one score per CVE a vulnerability maps to, so a non-CVE ID such as a GHSA
// can carry several. The second return is false when there is none.
func HighestEPSS(scores []vulnerability.EPSS) (float64, bool) {
	if len(scores) == 0 {
		return 0, false
	}
	highest := scores[0].EPSS
	for _, s := range scores[1:] {
		if s.EPSS > highest {
			highest = s.EPSS
		}
	}
	return highest, true
}

// exploitMetadata prefers the metadata embedded in the match and falls back
// to a provider lookup, as MatchSeverity does. It returns nil when neither
// source has it.
func exploitMetadata(m match.Match, vp vulnerability.Provider) *vulnerability.Metadata {
	if m.Vulnerability.Metadata != nil {
		return m.Vulnerability.Metadata
	}
	if vp == nil {
		return nil
	}
	//nolint:staticcheck // fallback for matches without embedded metadata
	metadata, err := vp.VulnerabilityMetadata(m.Vulnerability.Reference)
	if err != nil {
		return nil
	}
	return metadata
}

// CheckRiskGates evaluates the gates across every scanned image and returns
// the gate failure, or nil when the gates are disabled or none tripped.
func CheckRiskGates(gates RiskGates, imageScanData []cautils.ImageScanData, onlyFixable bool) error {
	if !gates.Enabled() {
		return nil
	}
	var result RiskGateResult
	for i := range imageScanData {
		result.Add(EvaluateRiskGates(gates, imageScanData[i].Matches, imageScanData[i].VulnerabilityProvider, onlyFixable))
	}
	return RiskGateFailure(gates, result)
}

// RiskGateFailure warns when the EPSS gate could not fail the scan because no
// checked match carried a score, and returns the gate failure for result, or
// nil when no gate tripped.
func RiskGateFailure(gates RiskGates, result RiskGateResult) error {
	if gates.EPSSThreshold > 0 && result.EPSSChecked > 0 && result.EPSSScored == 0 {
		logger.L().Warning("no matched vulnerability carries an EPSS score, so the EPSS threshold cannot fail this scan; the vulnerability database may not include EPSS data",
			helpers.Int("matches", result.EPSSChecked))
	}

	var reasons []string
	if result.KEV > 0 {
		reasons = append(reasons, fmt.Sprintf("%d vulnerability match(es) listed in CISA KEV", result.KEV))
	}
	if result.EPSS > 0 {
		reasons = append(reasons, fmt.Sprintf("%d vulnerability match(es) with an EPSS score at or above %s", result.EPSS, strconv.FormatFloat(gates.EPSSThreshold, 'g', -1, 64)))
	}
	if result.Indeterminate > 0 {
		reasons = append(reasons, fmt.Sprintf("%d vulnerability match(es) whose exploitability data could not be determined", result.Indeterminate))
	}
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("image scan result exceeds exploitability gates: %s", strings.Join(reasons, "; "))
}
