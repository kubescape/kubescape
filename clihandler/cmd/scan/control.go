package scan

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/spf13/cobra"
)

var (
	controlExample = `
  # Scan the 'privileged container' control
  kubescape scan control "privileged container"
	
  # Scan list of controls separated with a comma
  kubescape scan control "privileged container","allowed hostpath"
  
  # Scan list of controls using the control ID separated with a comma
  kubescape scan control C-0058,C-0057
  
  Run 'kubescape list controls' for the list of supported controls
  
  Control documentation:
  https://hub.armo.cloud/docs/controls
`
)

// controlCmd represents the control command
func getControlCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "control <control names list>/<control ids list>",
		Short:   "The controls you wish to use. Run 'kubescape list controls' for the list of supported controls",
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
			var scanInfo cautils.ScanInfo

			// flagValidationControl(scanInfo)
			scanInfo.PolicyIdentifier = []reporthandling.PolicyIdentifier{}

			if len(args) == 0 {
				scanInfo.ScanAll = true
			} else { // expected control or list of control sepparated by ","

				// Read controls from input args
				scanInfo.SetPolicyIdentifiers(strings.Split(args[0], ","), reporthandling.KindControl)

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

			results, err := clihandler.Scan(&scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}
			results.HandleResults()
			if results.GetRiskScore() > float32(scanInfo.FailThreshold) {
				return fmt.Errorf("scan risk-score %.2f is above permitted threshold %.2f", results.GetRiskScore(), scanInfo.FailThreshold)
			}
			return nil
		},
	}
}

// func flagValidationControl() {
// 	if 100 < scanInfo.FailThreshold {
// 		logger.L().Fatal("bad argument: out of range threshold")
// 	}
// }

// func setScanForFirstControl(scanInfo, controls []string) []reporthandling.PolicyIdentifier {
// 	newPolicy := reporthandling.PolicyIdentifier{}
// 	newPolicy.Kind = reporthandling.KindControl
// 	newPolicy.Name = controls[0]
// 	scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
// 	return scanInfo.PolicyIdentifier
// }

// func SetScanForGivenControls(scanInfo, controls []string) []reporthandling.PolicyIdentifier {
// 	for _, control := range controls {
// 		control := strings.TrimLeft(control, " ")
// 		newPolicy := reporthandling.PolicyIdentifier{}
// 		newPolicy.Kind = reporthandling.KindControl
// 		newPolicy.Name = control
// 		scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
// 	}
// 	return scanInfo.PolicyIdentifier
// }
