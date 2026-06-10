package shared

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
)

// ScanFormats and ImageScanFormats list the output formats supported by the scan commands.
// They are built from the printer.*Format constants to keep a single source of truth.
var (
	ScanFormats      = []string{printer.PrettyFormat, printer.JsonFormat, printer.JunitResultFormat, printer.PrometheusFormat, printer.PdfFormat, printer.HtmlFormat, printer.SARIFFormat}
	ImageScanFormats = []string{printer.PrettyFormat, printer.JsonFormat, printer.SARIFFormat}
)

var ErrUnknownSeverity = fmt.Errorf("unknown severity. Supported severities are: %s", strings.Join(reporthandlingapis.GetSupportedSeverities(), ", "))

// ErrBadThreshold is returned when a numeric threshold is outside the valid range [0, 100].
var ErrBadThreshold = fmt.Errorf("bad argument: out of range threshold")

// ValidateThresholds validates that FailThreshold, ComplianceThreshold and
// FailCoverageThreshold are all within [0, 100]. This mirrors the check in
// validateFrameworkScanInfo and validateControlScanInfo.
func ValidateThresholds(scanInfo *cautils.ScanInfo) error {
	if math.IsNaN(float64(scanInfo.FailThreshold)) || 100 < scanInfo.FailThreshold || 0 > scanInfo.FailThreshold {
		return ErrBadThreshold
	}
	if math.IsNaN(float64(scanInfo.ComplianceThreshold)) || 100 < scanInfo.ComplianceThreshold || 0 > scanInfo.ComplianceThreshold {
		return ErrBadThreshold
	}
	if math.IsNaN(float64(scanInfo.FailCoverageThreshold)) || 100 < scanInfo.FailCoverageThreshold || 0 > scanInfo.FailCoverageThreshold {
		return ErrBadThreshold
	}
	return nil
}

// ValidateSeverity returns an error if a given severity is not known, nil otherwise
func ValidateSeverity(severity string) error {
	for _, val := range reporthandlingapis.GetSupportedSeverities() {
		if strings.EqualFold(severity, val) {
			return nil
		}
	}
	return ErrUnknownSeverity

}

// ValidateScanFormat returns an error if any comma-separated entry in format is not a supported format.
func ValidateScanFormat(format string, supported []string) error {
	var entries int
	for _, f := range strings.Split(format, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		entries++
		if !slices.Contains(supported, f) {
			return fmt.Errorf("invalid format %q, supported formats: %s", f, strings.Join(supported, ", "))
		}
	}
	// Reject separator/whitespace-only input (e.g. "," or " ") that resolves to no format.
	// A truly empty value is left to the caller's "format cannot be empty" check.
	if entries == 0 && strings.TrimSpace(format) != "" {
		return fmt.Errorf("invalid format %q, supported formats: %s", format, strings.Join(supported, ", "))
	}
	return nil
}

// TerminateOnExceedingSeverity terminates the program if the result exceeds the severity threshold
func TerminateOnExceedingSeverity(scanInfo *cautils.ScanInfo, l helpers.ILogger) {
	l.Fatal("result exceeds severity threshold", helpers.String("Set severity threshold", scanInfo.FailThresholdSeverity))
}
