package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/spf13/cobra"
)

var downloadInfo cautils.DownloadInfo

var downloadCmd = &cobra.Command{
	Use:   fmt.Sprintf("download framework/control <framework-name>/<control-name> [flags]\nSupported frameworks: %s", getter.NativeFrameworks),
	Short: "Download framework/control",
	Long:  ``,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("requires two arguments : framework/control <framework-name>/<control-name>")
		}
		if !strings.EqualFold(args[0], "framework") && !strings.EqualFold(args[0], "control") {
			return fmt.Errorf("invalid parameter '%s'. Supported parameters: framework, control", args[0])
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := download(args); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(downloadCmd)
	downloadInfo = cautils.DownloadInfo{}
	downloadCmd.Flags().StringVarP(&downloadInfo.Path, "output", "o", "", "Output file. If specified, will store save to `~/.kubescape/<framework name>.json`")
}

func download(args []string) error {
	switch strings.ToLower(args[0]) {
	case "framework":
		return downloadFramework(args[1])
	case "control":
		return downloadControl(args[1])
	// case "exceptions":
	// case "artifacts":
	default:
		return fmt.Errorf("unknown command to download")
	}
}

func downloadFramework(frameworkName string) error {
	downloadInfo.FrameworkName = strings.ToLower(frameworkName)
	g := getter.NewDownloadReleasedPolicy()
	if err := g.SetRegoObjects(); err != nil {
		return err
	}

	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath(downloadInfo.FrameworkName + ".json")
	}
	frameworks, err := g.GetFramework(downloadInfo.FrameworkName)
	if err != nil {
		return err
	}
	err = getter.SaveFrameworkInFile(frameworks, downloadInfo.Path)
	if err != nil {
		return err
	}
	return nil
}

func downloadControl(controlName string) error {
	downloadInfo.ControlName = strings.ToLower(controlName)
	g := getter.NewDownloadReleasedPolicy()
	if err := g.SetRegoObjects(); err != nil {
		return err
	}
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath(downloadInfo.ControlName + ".json")
	}
	controls, err := g.GetControl(downloadInfo.ControlName)
	if err != nil {
		return err
	}
	err = getter.SaveControlInFile(controls, downloadInfo.Path)
	if err != nil {
		return err
	}
	return nil
}
