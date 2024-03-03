package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"golang.org/x/exp/slices"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/meta"

	"github.com/spf13/cobra"
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
	ErrKeepLocalOrSubmit        = errors.New("you can use `keep-local` or `submit`, but not both")
	ErrOmitRawResourcesOrSubmit = errors.New("you can use `omit-raw-resources` or `submit`, but not both")
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
					for _, framework := range frameworks {
						if framework == "" {
							return fmt.Errorf("usage: <framework-0>,<framework-1>")
						}
					}
				}
			} else {
				return fmt.Errorf("requires at least one framework name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := validateFrameworkScanInfo(scanInfo); err != nil {
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
				if len(args) > 1 {
					if args[1] != "-" {
						scanInfo.InputPatterns = args[1:]
						logger.L().Debug("List of input files", helpers.Interface("patterns", scanInfo.InputPatterns))
					} else { // store stdin to file - do NOT move to separate function !!
						tempFile, err := os.CreateTemp(".", "tmp-kubescape*.yaml")
						if err != nil {
							return err
						}
						defer os.Remove(tempFile.Name())

						if _, err := io.Copy(tempFile, os.Stdin); err != nil {
							return err
						}
						scanInfo.InputPatterns = []string{tempFile.Name()}
					}
				}
			}
			scanInfo.SetScanType(cautils.ScanTypeFramework)

			scanInfo.SetPolicyIdentifiers(frameworks, apisv1.KindFramework)

			ctx := context.TODO()
			results, err := ks.Scan(ctx, scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}

			if err = results.HandleResults(ctx); err != nil {
				logger.L().Fatal(err.Error())
			}

			if results.GetRiskScore() > float32(scanInfo.FailThreshold) {
				logger.L().Fatal("scan risk-score is above permitted threshold", helpers.String("risk-score", fmt.Sprintf("%.2f", results.GetRiskScore())), helpers.String("fail-threshold", fmt.Sprintf("%.2f", scanInfo.FailThreshold)))
			}
			if results.GetComplianceScore() < float32(scanInfo.ComplianceThreshold) {
				logger.L().Fatal("scan compliance-score is below permitted threshold", helpers.String("compliance-score", fmt.Sprintf("%.2f", results.GetComplianceScore())), helpers.String("compliance-threshold", fmt.Sprintf("%.2f", scanInfo.ComplianceThreshold)))
			}

			enforceSeverityThresholds(results.GetData().Report.SummaryDetails.GetResourcesSeverityCounters(), scanInfo, terminateOnExceedingSeverity)
			return nil
		},
	}

}

// countersExceedSeverityThreshold returns true if severity of failed controls exceed the set severity threshold, else returns false
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

// terminateOnExceedingSeverity terminates the application on exceeding severity
func terminateOnExceedingSeverity(scanInfo *cautils.ScanInfo, l helpers.ILogger) {
	l.Fatal("compliance result exceeds severity threshold", helpers.String("set severity threshold", scanInfo.FailThresholdSeverity))
}

// enforceSeverityThresholds ensures that the scan results are below the defined severity threshold
//
// The function forces the application to terminate with an exit code 1 if at least one control failed control that exceeds the set severity threshold
func enforceSeverityThresholds(severityCounters reportsummary.ISeverityCounters, scanInfo *cautils.ScanInfo, onExceed func(*cautils.ScanInfo, helpers.ILogger)) {
	// If a severity threshold is not set, we don’t need to enforce it
	if scanInfo.FailThresholdSeverity == "" {
		return
	}

	if val, err := countersExceedSeverityThreshold(severityCounters, scanInfo); val && err == nil {
		onExceed(scanInfo, logger.L())
	} else if err != nil {
		logger.L().Fatal(err.Error())
	}
}

// validateFrameworkScanInfo validates the scan info struct for the `scan framework` command
func validateFrameworkScanInfo(scanInfo *cautils.ScanInfo) error {
	if scanInfo.View == string(cautils.SecurityViewType) {
		scanInfo.View = string(cautils.ResourceViewType)
	}

	if scanInfo.Submit && scanInfo.Local {
		return ErrKeepLocalOrSubmit
	}
	if 100 < scanInfo.ComplianceThreshold || 0 > scanInfo.ComplianceThreshold {
		return ErrBadThreshold
	}
	if 100 < scanInfo.FailThreshold || 0 > scanInfo.FailThreshold {
		return ErrBadThreshold
	}
	if scanInfo.Submit && scanInfo.OmitRawResources {
		return ErrOmitRawResourcesOrSubmit
	}
	severity := scanInfo.FailThresholdSeverity
	if err := shared.ValidateSeverity(severity); severity != "" && err != nil {
		return err
	}

	// Validate the user's credentials
	return cautils.ValidateAccountID(scanInfo.AccountID)
}
