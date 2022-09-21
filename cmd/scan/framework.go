package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"

	"github.com/enescakir/emoji"
	"github.com/spf13/cobra"
)

var (
	frameworkExample = `
  # Scan all frameworks and submit the results
  kubescape scan framework all --submit
  
  # Scan the NSA framework
  kubescape scan framework nsa
  
  # Scan the NSA and MITRE framework
  kubescape scan framework nsa,mitre
  
  # Scan all frameworks
  kubescape scan framework all

  # Scan kubernetes YAML manifest files (single file or glob)
  kubescape scan framework nsa *.yaml

  Run 'kubescape list frameworks' for the list of supported frameworks
`

	ErrUnknownSeverity = errors.New("unknown severity")
)

func getFrameworkCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {

	return &cobra.Command{
		Use:     "framework <framework names list> [`<glob pattern>`/`-`] [flags]",
		Short:   "The framework you wish to use. Run 'kubescape list frameworks' for the list of supported frameworks",
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

			var frameworks []string

			if len(args) == 0 { // scan all frameworks
				scanInfo.ScanAll = true
			} else {
				// Read frameworks from input args
				frameworks = strings.Split(args[0], ",")
				if cautils.StringInSlice(frameworks, "all") != cautils.ValueNotFound {
					scanInfo.ScanAll = true
					frameworks = []string{}
				}
				if len(args) > 1 {
					if len(args[1:]) == 0 || args[1] != "-" {
						scanInfo.InputPatterns = args[1:]
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
			scanInfo.FrameworkScan = true

			scanInfo.SetPolicyIdentifiers(frameworks, apisv1.KindFramework)

			results, err := ks.Scan(scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}

			if err = results.HandleResults(); err != nil {
				logger.L().Fatal(err.Error())
			}
			if !scanInfo.VerboseMode {
				cautils.SimpleDisplay(os.Stderr, "%s  Run with '--verbose'/'-v' flag for detailed resources view\n\n", emoji.Detective)
			}
			if results.GetRiskScore() > float32(scanInfo.FailThreshold) {
				logger.L().Fatal("scan risk-score is above permitted threshold", helpers.String("risk-score", fmt.Sprintf("%.2f", results.GetRiskScore())), helpers.String("fail-threshold", fmt.Sprintf("%.2f", scanInfo.FailThreshold)))
			}

			enforceSeverityThresholds(&results.GetData().Report.SummaryDetails.SeverityCounters, scanInfo, terminateOnExceedingSeverity)
			return nil
		},
	}
}

// countersExceedSeverityThreshold returns true if severity of failed controls exceed the set severity threshold, else returns false
func countersExceedSeverityThreshold(severityCounters reportsummary.ISeverityCounters, scanInfo *cautils.ScanInfo) (bool, error) {
	targetSeverity := scanInfo.FailThresholdSeverity
	if err := validateSeverity(targetSeverity); err != nil {
		return false, err
	}

	getFailedResourcesFuncsBySeverity := []struct {
		SeverityName       string
		GetFailedResources func() int
	}{
		{reporthandlingapis.SeverityLowString, severityCounters.NumberOfResourcesWithLowSeverity},
		{reporthandlingapis.SeverityMediumString, severityCounters.NumberOfResourcesWithMediumSeverity},
		{reporthandlingapis.SeverityHighString, severityCounters.NumberOfResourcesWithHighSeverity},
		{reporthandlingapis.SeverityCriticalString, severityCounters.NumberOfResourcesWithCriticalSeverity},
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
func terminateOnExceedingSeverity(scanInfo *cautils.ScanInfo, l logger.ILogger) {
	l.Fatal("result exceeds severity threshold", helpers.String("set severity threshold", scanInfo.FailThresholdSeverity))
}

// enforceSeverityThresholds ensures that the scan results are below the defined severity threshold
//
// The function forces the application to terminate with an exit code 1 if at least one control failed control that exceeds the set severity threshold
func enforceSeverityThresholds(severityCounters reportsummary.ISeverityCounters, scanInfo *cautils.ScanInfo, onExceed func(*cautils.ScanInfo, logger.ILogger)) {
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

// validateSeverity returns an error if a given severity is not known, nil otherwise
func validateSeverity(severity string) error {
	for _, val := range reporthandlingapis.GetSupportedSeverities() {
		if strings.EqualFold(severity, val) {
			return nil
		}
	}
	return ErrUnknownSeverity

}

// validateFrameworkScanInfo validates the scan info struct for the `scan framework` command
func validateFrameworkScanInfo(scanInfo *cautils.ScanInfo) error {
	if scanInfo.Submit && scanInfo.Local {
		return fmt.Errorf("you can use `keep-local` or `submit`, but not both")
	}
	if 100 < scanInfo.FailThreshold || 0 > scanInfo.FailThreshold {
		return fmt.Errorf("bad argument: out of range threshold")
	}

	severity := scanInfo.FailThresholdSeverity
	if err := validateSeverity(severity); severity != "" && err != nil {
		return err
	}

	// Validate the user's credentials
	return scanInfo.Credentials.Validate()
}
