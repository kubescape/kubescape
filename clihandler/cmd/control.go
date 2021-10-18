package cmd

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/spf13/cobra"
)

// controlCmd represents the control command
var controlCmd = &cobra.Command{
	Use:   fmt.Sprint("control <control name>"),
	Short: fmt.Sprintf("The control you wish to use for scan. It must be present in at least one of the folloiwng frameworks: %s", clihandler.ValidFrameworks),
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("requires  one argument")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		flagValidationControl()
		scanInfo.FrameworkScan = false
		scanInfo.PolicyIdentifier = reporthandling.PolicyIdentifier{}
		scanInfo.PolicyIdentifier.Kind = reporthandling.KindControl
		scanInfo.PolicyIdentifier.Name = args[0]
		scanInfo.Init()
		cautils.SetSilentMode(scanInfo.Silent)
		err := clihandler.CliSetup(scanInfo)
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
