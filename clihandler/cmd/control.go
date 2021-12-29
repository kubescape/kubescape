package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/spf13/cobra"
)

// controlCmd represents the control command
var controlCmd = &cobra.Command{
	Use:   "control <control names list>/<control ids list>.\nExamples:\n$ kubescape scan control C-0058,C-0057 [flags]\n$ kubescape scan contol C-0058 [flags]\n$ kubescape scan control 'privileged container,allowed hostpath' [flags]",
	Short: fmt.Sprintf("The control you wish to use for scan. It must be present in at least one of the following frameworks: %s", getter.NativeFrameworks),
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			controls := strings.Split(args[0], ",")
			if len(controls) > 1 {
				if controls[1] == "" {
					return fmt.Errorf("usage: <control-0>,<control-1>")
				}
			}
		} else {
			return fmt.Errorf("requires at least one control name")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		flagValidationControl()
		scanInfo.PolicyIdentifier = []reporthandling.PolicyIdentifier{}

		if len(args) == 0 {
			scanInfo.SetPolicyIdentifiers(getter.NativeFrameworks, reporthandling.KindFramework)
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
		scanInfo.Init()
		cautils.SetSilentMode(scanInfo.Silent)
		err := clihandler.ScanCliSetup(&scanInfo)
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

func setScanForFirstControl(controls []string) []reporthandling.PolicyIdentifier {
	newPolicy := reporthandling.PolicyIdentifier{}
	newPolicy.Kind = reporthandling.KindControl
	newPolicy.Name = controls[0]
	scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
	return scanInfo.PolicyIdentifier
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
