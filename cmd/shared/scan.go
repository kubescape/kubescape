package shared

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/spf13/cobra"
)

// ScanFormats and ImageScanFormats are derived from printer.AllFormats and
// printer.ImageFormats to keep a single source of truth — see printresults.go
// for why the two lists differ (not every printer supports image scans, e.g. CSV).
var (
	ScanFormats      = printer.AllFormats
	ImageScanFormats = printer.ImageFormats
)

var ErrUnknownSeverity = fmt.Errorf("unknown severity. Supported severities are: %s", strings.Join(reporthandlingapis.GetSupportedSeverities(), ", "))

// ErrBadThreshold is returned when a numeric threshold is outside the valid range [0, 100].
var ErrBadThreshold = fmt.Errorf("bad argument: out of range threshold")

var (
	ErrKeepLocalOrSubmit        = fmt.Errorf("you can use `keep-local` or `submit`, but not both")
	ErrOmitRawResourcesOrSubmit = fmt.Errorf("you can use `omit-raw-resources` or `submit`, but not both")
)

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
	trimmed := strings.TrimSpace(severity)
	for _, val := range reporthandlingapis.GetSupportedSeverities() {
		if strings.EqualFold(trimmed, val) {
			return nil
		}
	}
	return ErrUnknownSeverity
}

// ValidateSeverityRange returns an error when min is greater than max, which
// would produce empty output rather than an obvious error. Both values must
// already have been validated by ValidateSeverity before this is called.
func ValidateSeverityRange(min, max string) error {
	if severityOrdinal(min) > severityOrdinal(max) {
		return fmt.Errorf("min severity cannot be greater than max severity (%s > %s)", min, max)
	}
	return nil
}

// severityOrdinal maps a severity string to the same integer ordinal used by
// reporthandlingapis.ControlSeverityToInt so that CLI-layer comparisons stay
// in sync with the core library. Unknown values map to SeverityUnknown (0).
func severityOrdinal(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case strings.ToLower(reporthandlingapis.SeverityCriticalString):
		return reporthandlingapis.SeverityCritical
	case strings.ToLower(reporthandlingapis.SeverityHighString):
		return reporthandlingapis.SeverityHigh
	case strings.ToLower(reporthandlingapis.SeverityMediumString):
		return reporthandlingapis.SeverityMedium
	case strings.ToLower(reporthandlingapis.SeverityLowString):
		return reporthandlingapis.SeverityLow
	default:
		return reporthandlingapis.SeverityUnknown
	}
}

// ValidateScanFormat returns an error if any comma-separated entry in format is not a supported format.
func ValidateScanFormat(format string, supported []string) error {
	var entries int
	for f := range strings.SplitSeq(format, ",") {
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

// ValidateCommonScanFlags validates flags that are common to all scan subcommands
func ValidateCommonScanFlags(cmd *cobra.Command, scanInfo *cautils.ScanInfo, supportedFormats []string) error {
	if scanInfo.Submit.GetBool() && scanInfo.Local {
		return ErrKeepLocalOrSubmit
	}
	if scanInfo.Submit.GetBool() && scanInfo.OmitRawResources {
		return ErrOmitRawResourcesOrSubmit
	}

	if scanInfo.FailThresholdSeverity != "" {
		if err := ValidateSeverity(scanInfo.FailThresholdSeverity); err != nil {
			return err
		}
	}
	if scanInfo.MinSeverity != "" {
		if err := ValidateSeverity(scanInfo.MinSeverity); err != nil {
			return err
		}
	}
	if scanInfo.MaxSeverity != "" {
		if err := ValidateSeverity(scanInfo.MaxSeverity); err != nil {
			return err
		}
	}
	if scanInfo.MinSeverity != "" && scanInfo.MaxSeverity != "" {
		if err := ValidateSeverityRange(scanInfo.MinSeverity, scanInfo.MaxSeverity); err != nil {
			return err
		}
	}
	f := cmd.Flags().Lookup("format")
	if f == nil {
		f = cmd.InheritedFlags().Lookup("format")
	}
	if f != nil && f.Changed && scanInfo.Format == "" {
		return fmt.Errorf("format cannot be empty, supported formats: %s", strings.Join(supportedFormats, ", "))
	}
	if err := ValidateScanFormat(scanInfo.Format, supportedFormats); err != nil {
		return err
	}
	return nil
}
