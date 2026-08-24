package resultshandling

import (
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

// buildScanOutcome reduces a finished scan to the measurements the OTLP
// exporter records. It reads the report after severity filters have been
// applied, so exported counts match what the user was shown.
func buildScanOutcome(scanData *cautils.OPASessionObj, imageScanData []cautils.ImageScanData, scanInfo *cautils.ScanInfo) telemetry.ScanOutcome {
	outcome := telemetry.ScanOutcome{
		Images: buildImageOutcomes(imageScanData, redactsIdentifiers(scanInfo)),
	}
	if scanInfo != nil {
		outcome.Target = string(scanInfo.ScanType)
	}
	if scanData == nil || scanData.Report == nil {
		return outcome
	}

	summary := &scanData.Report.SummaryDetails
	outcome.ComplianceScore = float64(summary.ComplianceScore)
	outcome.HasComplianceScore = true
	outcome.Controls = buildControlOutcomes(summary.ListControls())
	outcome.ResourcesByKind = countResourcesByKind(scanData)
	return outcome
}

func buildControlOutcomes(controls []reportsummary.IControlSummary) []telemetry.ControlOutcome {
	outcomes := make([]telemetry.ControlOutcome, 0, len(controls))
	for _, control := range controls {
		status := ""
		if controlStatus := control.GetStatus(); controlStatus != nil {
			status = string(controlStatus.Status())
		}
		outcomes = append(outcomes, telemetry.ControlOutcome{
			Severity: apis.ControlSeverityToString(control.GetScoreFactor()),
			Status:   status,
		})
	}
	return outcomes
}

func countResourcesByKind(scanData *cautils.OPASessionObj) map[string]int64 {
	// Sized for the number of distinct kinds, not the resource count: a large
	// cluster has tens of thousands of resources across a few dozen kinds.
	counts := make(map[string]int64, 32)
	for _, resource := range scanData.AllResources {
		if resource == nil {
			continue
		}
		counts[resource.GetKind()]++
	}
	return counts
}

// redactsIdentifiers reports whether the user asked for the report's own
// identifiers to be anonymized or encrypted. Telemetry has to honour that too:
// --hide exists so image references do not leave the machine in the clear, and
// a metric attribute is just as much an egress as the report file.
func redactsIdentifiers(scanInfo *cautils.ScanInfo) bool {
	return scanInfo != nil && (scanInfo.Hide || scanInfo.EncryptionEnabled)
}

func buildImageOutcomes(imageScanData []cautils.ImageScanData, redact bool) []telemetry.ImageOutcome {
	if len(imageScanData) == 0 {
		return nil
	}

	// Redacted runs collapse into a single unnamed series. That keeps the
	// severity totals useful while dropping the per-image attribution, which
	// also bounds a label whose cardinality is otherwise the image count.
	if redact {
		return []telemetry.ImageOutcome{aggregateImages(imageScanData)}
	}

	outcomes := make([]telemetry.ImageOutcome, 0, len(imageScanData))
	for _, data := range imageScanData {
		outcome := newImageOutcome(data.Image)
		countMatches(&outcome, data)
		outcomes = append(outcomes, outcome)
	}
	return outcomes
}

func aggregateImages(imageScanData []cautils.ImageScanData) telemetry.ImageOutcome {
	outcome := newImageOutcome("")
	for _, data := range imageScanData {
		countMatches(&outcome, data)
	}
	return outcome
}

func newImageOutcome(image string) telemetry.ImageOutcome {
	return telemetry.ImageOutcome{
		Image:             image,
		BySeverity:        map[string]int64{},
		FixableBySeverity: map[string]int64{},
	}
}

func countMatches(outcome *telemetry.ImageOutcome, data cautils.ImageScanData) {
	for _, m := range data.Matches.Sorted() {
		// Metadata is resolved from the vulnerability database and is nil for
		// matches the provider could not enrich; telemetry must not be the
		// thing that panics on them.
		severity := ""
		if m.Vulnerability.Metadata != nil {
			severity = m.Vulnerability.Metadata.Severity
		}
		outcome.BySeverity[severity]++
		if m.Vulnerability.Fix.State == vulnerability.FixStateFixed {
			outcome.FixableBySeverity[severity]++
		}
	}
}
