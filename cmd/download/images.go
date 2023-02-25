package download

import (
	"github.com/kubescape/kubescape/v2/core/meta"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var (
	imageExample = `
  # Download the image vulnerabilities results in requested format
  kubescape download images

  # Download the image vulnerabilities results in JSON and output to a file
  kubescape download images --format=json --output=./imageResults.json

  # Download the view the image vulnerabilities results in pretty-print
  kubescape download images --format=pretty-print
`
)

// imageCmd represents the control command
func getImagesCmd(ks meta.IKubescape, downloadInfo *v1.DownloadInfo) *cobra.Command {

	imageCmd := &cobra.Command{
		Use:     "images",
		Short:   "Downloads the image vulnerabilities results",
		Example: imageExample,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			return ks.DownloadImages(downloadInfo)

		},
	}

	imageCmd.Flags().StringVarP(&downloadInfo.Path, "output", "o", "", "Output file.`")
	imageCmd.Flags().StringVar(&downloadInfo.Format, "format", "pretty-print", "output format. supported: 'pretty-print'/'json'")

	return imageCmd
}
