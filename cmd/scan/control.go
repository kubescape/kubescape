package scan

import (
	"fmt"
	"io"
	"os"
	"strings"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"

	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/meta"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	"github.com/enescakir/emoji"
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
  https://hub.armosec.io/docs/controls
`
)

// controlCmd represents the control command
func getControlCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
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

			// flagValidationControl(scanInfo)
			scanInfo.PolicyIdentifier = []cautils.PolicyIdentifier{}

			if len(args) == 0 {
				scanInfo.ScanAll = true
			} else { // expected control or list of control sepparated by ","

				// Read controls from input args
				scanInfo.SetPolicyIdentifiers(strings.Split(args[0], ","), apisv1.KindControl)

				if len(args) > 1 {
					if len(args[1:]) == 0 || args[1] != "-" {
						scanInfo.InputPatterns = []string{args[1]}
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

			results, err := ks.Scan(scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}
			if err := results.HandleResults(); err != nil {
				logger.L().Fatal(err.Error())
			}
			if !scanInfo.VerboseMode {
				cautils.SimpleDisplay(os.Stderr, "%s  Run with '--verbose'/'-v' flag for detailed resources view\n\n", emoji.Detective)
			}
			if results.GetRiskScore() > float32(scanInfo.FailThreshold) {
				logger.L().Fatal("scan risk-score is above permitted threshold", helpers.String("risk-score", fmt.Sprintf("%.2f", results.GetRiskScore())), helpers.String("fail-threshold", fmt.Sprintf("%.2f", scanInfo.FailThreshold)))
			}
			return nil
		},
	}
}
