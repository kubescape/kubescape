package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/spf13/cobra"
)

var downloadInfo cautils.DownloadInfo

var downloadCmd = &cobra.Command{
	Use:   "download framework <framework-name>",
	Short: "Download framework controls",
	Long:  ``,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("requires two arguments : framework <framework-name>")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		downloadInfo.FrameworkName = args[1]
		g := getter.NewDownloadReleasedPolicy()
		if !(cmd.Flags().Lookup("output").Changed) {
			downloadInfo.Path = cautils.GetDefaultPath(downloadInfo.FrameworkName)
		} else {
			currPath, err := os.Getwd()
			if err != nil {
				downloadInfo.Path = filepath.Join(downloadInfo.Path)
			} else {
				downloadInfo.Path = filepath.Join(currPath, downloadInfo.Path)
			}

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
	},
}

func init() {
	rootCmd.AddCommand(downloadCmd)
	downloadInfo = cautils.DownloadInfo{}
	downloadCmd.Flags().StringVarP(&downloadInfo.Path, "output", "o", "", "Output file.")
}
