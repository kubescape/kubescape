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
	Use:   "control <control name>/<control id>",
	Short: fmt.Sprintf("The control you wish to use for scan. It must be present in at least one of the folloiwng frameworks: %s", clihandler.ValidFrameworks),
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 && !(cmd.Flags().Lookup("use-from").Changed) {
			return fmt.Errorf("requires at least one argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		flagValidationControl()
		scanInfo.PolicyIdentifier = reporthandling.PolicyIdentifier{}
		if !(cmd.Flags().Lookup("use-from").Changed) {
			scanInfo.PolicyIdentifier.Name = strings.ToLower(args[0])
		}
		scanInfo.FrameworkScan = false
		scanInfo.PolicyIdentifier.Kind = reporthandling.KindControl
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
