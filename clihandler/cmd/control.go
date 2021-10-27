package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/spf13/cobra"
)

// controlCmd represents the control command
var controlCmd = &cobra.Command{
	Use:   "control <control names list>/<control ids list>.\nExamples:\nscan control C-0058,C-0057 [flags]\nscan contol C-0058 [flags]\nscan control 'privileged container,allowed hostpath' [flags]",
	Short: fmt.Sprintf("The control you wish to use for scan. It must be present in at least one of the folloiwng frameworks: %s", clihandler.ValidFrameworks),
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			controls := strings.Split(args[0], ",")
			if len(controls) > 1 {
				if controls[1] == "" {
					return fmt.Errorf("usage: <control_one>,<control_two>")
				}
			}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		flagValidationControl()
		scanInfo.PolicyIdentifier = []reporthandling.PolicyIdentifier{}

		if len(args) < 1 && !(cmd.Flags().Lookup("use-from").Changed) {
			scanInfo.PolicyIdentifier = SetScanForGivenFrameworks(clihandler.SupportedFrameworks)
		} else {
			var controls []string
			if len(args) > 0 {
				controls = strings.Split(args[0], ",")
				scanInfo.PolicyIdentifier = []reporthandling.PolicyIdentifier{}
				newPolicy := reporthandling.PolicyIdentifier{}
				newPolicy.Kind = reporthandling.KindControl
				newPolicy.Name = controls[0]
				scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
			}

			if !(cmd.Flags().Lookup("use-from").Changed) {
				if len(controls) > 1 {
					scanInfo.PolicyIdentifier = SetScanForGivenControls(controls[1:])
				}
			}
		}
		scanInfo.FrameworkScan = false
		scanInfo.Init()
		cautils.SetSilentMode(scanInfo.Silent)
		err := clihandler.CliSetup(&scanInfo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	scanInfo = cautils.ScanInfo{}
	scanCmd.AddCommand(controlCmd)
}

func flagValidationControl() {
	if 100 < scanInfo.FailThreshold {
		fmt.Println("bad argument: out of range threshold")
		os.Exit(1)
	}
}

func SetScanForGivenControls(controls []string) []reporthandling.PolicyIdentifier {
	for _, control := range controls {
		control := strings.TrimLeft(control, " ")
		newPolicy := reporthandling.PolicyIdentifier{}
		newPolicy.Kind = reporthandling.KindControl
		newPolicy.Name = control
		scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
	}
	return scanInfo.PolicyIdentifier
}
