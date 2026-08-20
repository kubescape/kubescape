package scan

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/meta"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"
)

var (
	frameworkExample = fmt.Sprintf(`
  # Scan all frameworks
  %[1]s scan framework all
  
  # Scan the NSA framework
  %[1]s scan framework nsa
  
  # Scan the NSA and MITRE framework
  %[1]s scan framework nsa,mitre
  
  # Scan all frameworks
  %[1]s scan framework all

  # Scan kubernetes YAML manifest files (single file or glob)
  %[1]s scan framework nsa .

  Run '%[1]s list frameworks' for the list of supported frameworks
`, cautils.ExecName())

	ErrSecurityViewNotSupported = errors.New("security view is not supported for framework scan")
	ErrBadThreshold             = errors.New("bad argument: out of range threshold")
	ErrControlTimeoutTooHigh    = errors.New("--control-timeout must be lower than --scan-timeout")
)

func getFrameworkCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {

	return &cobra.Command{
		Use:     "framework <framework names list> [`<glob pattern>`/`-`] [flags]",
		Short:   fmt.Sprintf("The framework you wish to use. Run '%[1]s list frameworks' for the list of supported frameworks", cautils.ExecName()),
		Example: frameworkExample,
		Long:    "Execute a scan on a running Kubernetes cluster or `yaml`/`json` files (use glob) or `-` for stdin",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				frameworks := strings.Split(args[0], ",")
				if len(frameworks) > 1 {
					if slices.Contains(frameworks, "") {
						return fmt.Errorf("usage: <framework-0>,<framework-1>")
					}
				}
			} else {
				return fmt.Errorf("requires at least one framework name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			defer applyTimeout(scanInfo, ks)()

			if err := shared.ValidateCommonScanFlags(cmd, scanInfo, shared.ScanFormats); err != nil {
				return err
			}
			if err := validateFrameworkScanInfo(scanInfo); err != nil {
				return err
			}
			if err := validateCombinedImageScanFlags(scanInfo); err != nil {
				return err
			}
			scanInfo.FrameworkScan = true

			// We do not scan all frameworks by default when triggering scan from the CLI
			scanInfo.ScanAll = false

			var frameworks []string

			if len(args) == 0 {
				scanInfo.ScanAll = true
			} else {
				// Read frameworks from input args
				frameworks = strings.Split(args[0], ",")
				if slices.Contains(frameworks, "all") {
					scanInfo.ScanAll = true
					frameworks = getter.NativeFrameworks

				}
				cleanup, err := prepareScanLocalInput(cmd.InOrStdin(), args, scanInfo, scanLocalInputOptions{
					FirstInputArg:    1,
					RejectMixedStdin: true,
				})
				if err != nil {
					return err
				}
				defer cleanup()
				if len(scanInfo.InputPatterns) > 0 {
					logger.L().Debug("List of input files", helpers.Interface("patterns", scanInfo.InputPatterns))
				}
			}
			scanInfo.SetScanType(cautils.ScanTypeFramework)

			policyIdentifiers := cautils.BuildPolicyIdentifiers(frameworks, apisv1.KindFramework)

			results, err := ks.Scan(scanInfo, policyIdentifiers)
			if err != nil {
				return err
			}

			if err = handleResultsWithReportingSpan(ks.Context(), results, scanInfo); err != nil {
				return err
			}

			if results.GetComplianceScore() < float32(scanInfo.ComplianceThreshold) {
				return fmt.Errorf("scan compliance-score is below permitted threshold: %.2f (compliance-threshold: %.2f)", results.GetComplianceScore(), scanInfo.ComplianceThreshold)
			}

			if err := enforceSeverityThresholds(&results.GetData().Report.SummaryDetails, scanInfo); err != nil {
				return err
			}
			if scanInfo.ScanImages {
				if err := enforceImageSeverityThresholds(results.ImageScanData, scanInfo); err != nil {
					return err
				}
			}
			if err := enforceCoverageThreshold(results.GetData().ScanCoverage, len(results.GetData().Report.SummaryDetails.Controls), scanInfo); err != nil {
				return err
			}
			if err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
				return err
			}
			return enforceBaselineDrift(ks.Context(), results, scanInfo)
		},
	}

}

// countersExceedSeverityThreshold returns true if a failed control has severity
// at or above the configured threshold.
func countersExceedSeverityThreshold(severityCounters reportsummary.ISeverityCounters, scanInfo *cautils.ScanInfo) (bool, error) {
	targetSeverity := scanInfo.FailThresholdSeverity
	if err := shared.ValidateSeverity(targetSeverity); err != nil {
		return false, err
	}

	getFailedResourcesFuncsBySeverity := []struct {
		SeverityName       string
		GetFailedResources func() int
	}{
		{reporthandlingapis.SeverityLowString, severityCounters.NumberOfLowSeverity},
		{reporthandlingapis.SeverityMediumString, severityCounters.NumberOfMediumSeverity},
		{reporthandlingapis.SeverityHighString, severityCounters.NumberOfHighSeverity},
		{reporthandlingapis.SeverityCriticalString, severityCounters.NumberOfCriticalSeverity},
	}

	targetSeverityIdx := 0
	for idx, description := range getFailedResourcesFuncsBySeverity {
		if strings.EqualFold(description.SeverityName, targetSeverity) {
			targetSeverityIdx = idx
			break
		}
	}

	for _, description := range getFailedResourcesFuncsBySeverity[targetSeverityIdx:] {
		failedResourcesCount := description.GetFailedResources()
		if failedResourcesCount > 0 {
			return true, nil
		}
	}

	return false, nil

}

// enforceCoverageThreshold fails the scan if the scan coverage score is below
// scanInfo.FailCoverageThreshold. The score is computed once in the scan
// pipeline (ScanCoverage.ComputeCoverageScore) so this gate agrees with what
// the JSON, Prometheus and pretty-printer outputs report. A threshold of 0
// disables the check.
func enforceCoverageThreshold(coverage cautils.ScanCoverage, totalControls int, scanInfo *cautils.ScanInfo) error {
	if scanInfo.FailCoverageThreshold <= 0 {
		return nil
	}
	if totalControls == 0 {
		return fmt.Errorf("scan loaded no controls: coverage is 0%% (fail-coverage-below: %.2f%%)", scanInfo.FailCoverageThreshold)
	}
	if coverage.CoverageScore < scanInfo.FailCoverageThreshold {
		return fmt.Errorf("scan coverage is below permitted threshold: %.2f%% (fail-coverage-below: %.2f%%)", coverage.CoverageScore, scanInfo.FailCoverageThreshold)
	}
	return nil
}

// enforcePolicyDegradation fails the scan if control configurations or
// exceptions could not be loaded from their configured source and the scan
// proceeded with bundled defaults instead.
func enforcePolicyDegradation(coverage cautils.ScanCoverage, scanInfo *cautils.ScanInfo) error {
	if !scanInfo.FailOnDegradedConfig || len(coverage.PolicyDegradations) == 0 {
		return nil
	}
	for _, d := range coverage.PolicyDegradations {
		logger.L().Warning("policy input degraded, bundled defaults were used", helpers.String("component", d.Component), helpers.String("reason", d.Reason))
	}
	return fmt.Errorf("scan policy inputs were degraded (fail-on-degraded-config is true)")
}

// countFailedResourcesWithUnbucketedSeverity returns the number of failed
// resources on controls whose severity SeverityCounters.Increase silently
// drops: Unknown, Negligible, and any other severity it has no bucket for.
// The severity is derived from the control's score factor the same way
// SummaryDetails.AppendResourceResult derives it when feeding the counters.
func countFailedResourcesWithUnbucketedSeverity(summaryDetails *reportsummary.SummaryDetails) int {
	count := 0
	for _, controlSummary := range summaryDetails.Controls {
		switch reporthandlingapis.ControlSeverityToString(controlSummary.GetScoreFactor()) {
		case reporthandlingapis.SeverityCriticalString,
			reporthandlingapis.SeverityHighString,
			reporthandlingapis.SeverityMediumString,
			reporthandlingapis.SeverityLowString:
		default:
			count += controlSummary.StatusCounters.Failed()
		}
	}
	return count
}

// enforceSeverityThresholds ensures that the scan results are below the defined severity threshold
//
// The function returns an error if at least one failed control has a severity at or above the set severity threshold
func enforceSeverityThresholds(summaryDetails *reportsummary.SummaryDetails, scanInfo *cautils.ScanInfo) error {
	// If a severity threshold is not set, we don’t need to enforce it
	if scanInfo.FailThresholdSeverity == "" {
		return nil
	}

	if val, err := countersExceedSeverityThreshold(summaryDetails.GetResourcesSeverityCounters(), scanInfo); val && err == nil {
		return fmt.Errorf("compliance result exceeds severity threshold: %s", scanInfo.FailThresholdSeverity)
	} else if err != nil {
		return err
	}

	// Failed controls with a zero or missing baseScore never reach the
	// counters above, so a threshold could pass on findings whose severity
	// cannot be determined. Fail closed: treat them as at or above any
	// threshold the user set.
	if unbucketed := countFailedResourcesWithUnbucketedSeverity(summaryDetails); unbucketed > 0 {
		logger.L().Warning("failed resources with unknown severity counted toward the severity threshold", helpers.Int("failedResources", unbucketed))
		return fmt.Errorf("compliance result exceeds severity threshold: %s (%d failed resource(s) with unknown severity)", scanInfo.FailThresholdSeverity, unbucketed)
	}
	return nil
}

// validateFrameworkScanInfo validates the scan info struct for the `scan framework` command
func validateFrameworkScanInfo(scanInfo *cautils.ScanInfo) error {
	if scanInfo.View == string(cautils.SecurityViewType) {
		scanInfo.View = string(cautils.ResourceViewType)
	}
	if postureThresholdsOutOfRange(scanInfo) {
		return ErrBadThreshold
	}
	if err := validateControlTimeout(scanInfo); err != nil {
		return err
	}
	severity := scanInfo.FailThresholdSeverity
	if err := shared.ValidateSeverity(severity); severity != "" && err != nil {
		return err
	}

	if scanInfo.LabelSelector != "" {
		if _, err := labels.Parse(scanInfo.LabelSelector); err != nil {
			return fmt.Errorf("invalid --label-selector %q: %w", scanInfo.LabelSelector, err)
		}
	}

	// Validate the user's credentials
	return cautils.ValidateAccountID(scanInfo.AccountID)
}

// validateControlTimeout ensures --control-timeout, when set alongside
// --scan-timeout, leaves room for at least one control to be evaluated
// before the overall scan deadline expires.
func validateControlTimeout(scanInfo *cautils.ScanInfo) error {
	if scanInfo.ControlTimeout > 0 && scanInfo.ScanTimeout > 0 && scanInfo.ControlTimeout >= scanInfo.ScanTimeout {
		return ErrControlTimeoutTooHigh
	}
	return nil
}

// validateThresholdsOnly validates only the numeric threshold ranges
// (compliance-threshold and fail-coverage-threshold must be between 0 and 100).
// Unlike validateFrameworkScanInfo, this function does not mutate scanInfo
// or enforce unrelated constraints.
func validateThresholdsOnly(scanInfo *cautils.ScanInfo) error {
	if postureThresholdsOutOfRange(scanInfo) {
		return ErrBadThreshold
	}
	return validateControlTimeout(scanInfo)
}

func postureThresholdsOutOfRange(scanInfo *cautils.ScanInfo) bool {
	return math.IsNaN(float64(scanInfo.ComplianceThreshold)) ||
		math.IsNaN(float64(scanInfo.FailCoverageThreshold)) ||
		scanInfo.ComplianceThreshold < 0 || scanInfo.ComplianceThreshold > 100 ||
		scanInfo.FailCoverageThreshold < 0 || scanInfo.FailCoverageThreshold > 100
}
