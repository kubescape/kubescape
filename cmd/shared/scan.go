package shared

import (
	"fmt"
	"math"
	"strings"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
)

// supportedScanFormats lists all valid output formats for scan commands.
var supportedScanFormats = []string{
	printer.PrettyFormat,
	printer.JsonFormat,
	printer.JunitResultFormat,
	printer.PrometheusFormat,
	printer.PdfFormat,
	printer.HtmlFormat,
	printer.SARIFFormat,
}

// ErrInvalidScanFormat is returned when the format flag is set to an unsupported value.
var ErrInvalidScanFormat = fmt.Errorf("invalid format. Supported formats: %s", strings.Join(supportedScanFormats, ", "))

// ValidateScanFormat returns an error if the given format string is not a supported scan output format.
// It also normalizes the format to lowercase so downstream printers receive a consistent value.
func ValidateScanFormat(format string) (string, error) {
	for _, f := range supportedScanFormats {
		if strings.EqualFold(format, f) {
			return f, nil
		}
	}
	return "", ErrInvalidScanFormat
}

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

// TerminateOnExceedingSeverity terminates the program if the result exceeds the severity threshold
func TerminateOnExceedingSeverity(scanInfo *cautils.ScanInfo, l helpers.ILogger) {
	l.Fatal("result exceeds severity threshold", helpers.String("Set severity threshold", scanInfo.FailThresholdSeverity))
}
