package cmd

import (
	"fmt"
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
		if strings.EqualFold(args[0], "framework") {
			downloadInfo.FrameworkName = strings.ToLower(args[1])
			g := getter.NewDownloadReleasedPolicy()
			if downloadInfo.Path == "" {
				downloadInfo.Path = getter.GetDefaultPath(getter.GetFilename(downloadInfo.FrameworkName))
			}
			frameworks, err := g.GetFramework(downloadInfo.FrameworkName)
			if err != nil {
				return err
			}
			err = getter.SaveFrameworkInFile(frameworks, downloadInfo.Path)
			if err != nil {
				return err
			}
		} else if strings.EqualFold(args[0], "control") {
			downloadInfo.ControlName = strings.ToLower(args[1])
			g := getter.NewDownloadReleasedPolicy()
			if downloadInfo.Path == "" {
				downloadInfo.Path = getter.GetDefaultPath(getter.GetFilename(downloadInfo.ControlName))
			}
			controls, err := g.GetControl(downloadInfo.ControlName)
			if err != nil {
				return err
			}
			err = getter.SaveControlInFile(controls, downloadInfo.Path)
			if err != nil {
				return err
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(downloadCmd)
	downloadInfo = cautils.DownloadInfo{}
	downloadCmd.Flags().StringVarP(&downloadInfo.Path, "output", "o", "", "Output file. If specified, will store save to `~/.kubescape/<framework name>.json`")
}
