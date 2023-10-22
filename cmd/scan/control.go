package scan

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"

	"github.com/spf13/cobra"
)

var (
	controlExample = fmt.Sprintf(`
  # Scan the 'privileged container' control
  %[1]s scan control "privileged container"
	
  # Scan list of controls separated with a comma
  %[1]s scan control "privileged container","HostPath mount"
  
  # Scan list of controls using the control ID separated with a comma
  %[1]s scan control C-0058,C-0057
  
  Run '%[1]s list controls' for the list of supported controls
  
  Control documentation:
  https://hub.armosec.io/docs/controls
`, cautils.ExecName())
)

// controlCmd represents the control command
func getControlCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	return &cobra.Command{
		Use:     "control <control names list>/<control ids list>",
		Short:   fmt.Sprintf("The controls you wish to use. Run '%[1]s list controls' for the list of supported controls", cautils.ExecName()),
		Example: controlExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				controls := strings.Split(args[0], ",")
				if len(controls) > 1 {
					for _, control := range controls {
						if control == "" {
							return fmt.Errorf("usage: <control-0>,<control-1>")
						}
					}
				}
			} else {
				return fmt.Errorf("requires at least one control name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := validateFrameworkScanInfo(scanInfo); err != nil {
				return err
			}

			// flagValidationControl(scanInfo)
			scanInfo.PolicyIdentifier = []cautils.PolicyIdentifier{}

			if len(args) == 0 {
				scanInfo.ScanAll = true
			} else { // expected control or list of control separated by ","

				// Read controls from input args
				scanInfo.SetPolicyIdentifiers(strings.Split(args[0], ","), apisv1.KindControl)

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

			scanInfo.FrameworkScan = false
			scanInfo.SetScanType(cautils.ScanTypeControl)

			if err := validateControlScanInfo(scanInfo); err != nil {
				return err
			}

			ctx := context.TODO()
			results, err := ks.Scan(ctx, scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}
			if err := results.HandleResults(ctx); err != nil {
				logger.L().Fatal(err.Error())
			}
			if !scanInfo.VerboseMode {
				logger.L().Info("Run with '--verbose'/'-v' flag for detailed resources view\n")
			}
			if results.GetRiskScore() > float32(scanInfo.FailThreshold) {
				logger.L().Fatal("scan risk-score is above permitted threshold", helpers.String("risk-score", fmt.Sprintf("%.2f", results.GetRiskScore())), helpers.String("fail-threshold", fmt.Sprintf("%.2f", scanInfo.FailThreshold)))
			}
			if results.GetComplianceScore() < float32(scanInfo.ComplianceThreshold) {
				logger.L().Fatal("scan compliance-score is below permitted threshold", helpers.String("compliance score", fmt.Sprintf("%.2f", results.GetComplianceScore())), helpers.String("compliance-threshold", fmt.Sprintf("%.2f", scanInfo.ComplianceThreshold)))
			}
			enforceSeverityThresholds(results.GetResults().SummaryDetails.GetResourcesSeverityCounters(), scanInfo, terminateOnExceedingSeverity)

			return nil
		},
	}
}

// validateControlScanInfo validates the ScanInfo struct for the `control` command
func validateControlScanInfo(scanInfo *cautils.ScanInfo) error {
	severity := scanInfo.FailThresholdSeverity

	if scanInfo.Submit && scanInfo.OmitRawResources {
		return fmt.Errorf("you can use `omit-raw-resources` or `submit`, but not both")
	}

	if err := shared.ValidateSeverity(severity); severity != "" && err != nil {
		return err
	}
	return nil
}
