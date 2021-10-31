package cmd

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/clihandler"
	"github.com/spf13/cobra"
)

var scanInfo cautils.ScanInfo

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan <command>",
	Short: "Scan the current running cluster or yaml files",
	Long:  `The action you want to perform`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			if !strings.EqualFold(args[0], "framework") && !strings.EqualFold(args[0], "control") {
				return fmt.Errorf("invalid parameter '%s'. Supported parameters: framework, control", args[0])
			}
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			frameworkArgs := []string{clihandler.ValidFrameworks}
			frameworkArgs = append(frameworkArgs, args...)
			frameworkCmd.RunE(cmd, frameworkArgs)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVarP(&scanInfo.ExcludedNamespaces, "exclude-namespaces", "e", "", "Namespaces to exclude from scanning. Recommended: kube-system, kube-public")
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", `Output format. Supported formats: "pretty-printer"/"json"/"junit"`)
	scanCmd.PersistentFlags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. Print output to file and not stdout")
	scanCmd.PersistentFlags().BoolVarP(&scanInfo.Silent, "silent", "s", false, "Silent progress messages")
	scanCmd.PersistentFlags().Uint16VarP(&scanInfo.FailThreshold, "fail-threshold", "t", 0, "Failure threshold is the percent bellow which the command fails and returns exit code 1")
	scanCmd.PersistentFlags().StringSliceVar(&scanInfo.UseFrom, "use-from", nil, "Load local policy object from specified path. If not used will download latest")
	scanCmd.PersistentFlags().BoolVar(&scanInfo.UseDefault, "use-default", false, "Load local policy object from default path. If not used will download latest")
	scanCmd.PersistentFlags().StringVar(&scanInfo.UseExceptions, "exceptions", "", "Path to an exceptions obj. If not set will download exceptions from ARMO management portal")
	scanCmd.PersistentFlags().StringVar(&scanInfo.ControlsInputs, "controls-config", "", "Path to an controls-config obj. If not set will download controls-config from ARMO management portal")
}
