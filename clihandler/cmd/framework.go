package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/opa-utils/reporthandling"

	"github.com/spf13/cobra"
)

var frameworkCmd = &cobra.Command{

	Use:       fmt.Sprintf("framework <framework name> [`<glob pattern>`/`-`] [flags]\nSupported frameworks: %s", clihandler.ValidFrameworks),
	Short:     fmt.Sprintf("The framework you wish to use. Supported frameworks: %s", strings.Join(clihandler.SupportedFrameworks, ", ")),
	Long:      "Execute a scan on a running Kubernetes cluster or `yaml`/`json` files (use glob) or `-` for stdin",
	ValidArgs: clihandler.SupportedFrameworks,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 && !(cmd.Flags().Lookup("use-from").Changed) {
			return fmt.Errorf("requires at least one argument")
		} else if len(args) > 0 {
			if !isValidFramework(strings.ToLower(args[0])) {
				return fmt.Errorf(fmt.Sprintf("supported frameworks: %s", strings.Join(clihandler.SupportedFrameworks, ", ")))
			}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		scanInfo.PolicyIdentifier = reporthandling.PolicyIdentifier{}
		scanInfo.PolicyIdentifier.Kind = reporthandling.KindFramework
		flagValidationFramework()
		if !(cmd.Flags().Lookup("use-from").Changed) {
			scanInfo.PolicyIdentifier.Name = strings.ToLower(args[0])
		}
		if len(args) > 0 {
			if len(args[1:]) == 0 || args[1] != "-" {
				scanInfo.InputPatterns = args[1:]
			} else { // store stout to file
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

func isValidFramework(framework string) bool {
	return cautils.StringInSlice(clihandler.SupportedFrameworks, framework) != cautils.ValueNotFound
}

func init() {
	scanCmd.AddCommand(frameworkCmd)
	scanInfo = cautils.ScanInfo{}
	scanInfo.FrameworkScan = true
	frameworkCmd.Flags().BoolVarP(&scanInfo.Submit, "submit", "", false, "Send the scan results to Armo management portal where you can see the results in a user-friendly UI, choose your preferred compliance framework, check risk results history and trends, manage exceptions, get remediation recommendations and much more. By default the results are not submitted")
	frameworkCmd.Flags().BoolVarP(&scanInfo.Local, "keep-local", "", false, "If you do not want your Kubescape results reported to Armo backend. Use this flag if you ran with the '--submit' flag in the past and you do not want to submit your current scan results")
	frameworkCmd.Flags().StringVarP(&scanInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")

}

func flagValidationFramework() {

	if scanInfo.Submit && scanInfo.Local {
		fmt.Println("You can use `keep-local` or `submit`, but not both")
		os.Exit(1)
	}
	if 100 < scanInfo.FailThreshold {
		fmt.Println("bad argument: out of range threshold")
		os.Exit(1)
	}
}
