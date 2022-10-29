package scan

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"

	"github.com/spf13/cobra"
)

var (
	imageExample = `
  # Display the image vulnerabilities scan results
  kubescape scan image

  # Display the results in JSON format
  kubescape scan image -f json

  # Display the results in pretty-printer format
  kubescape scan image -f "pretty-printer"
`
)

// imageCmd represents the image command
func getImageCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {

	return &cobra.Command{
		Use:     "image",
		Short:   "Displays the image vulnerabilities scan results. Run 'kubescape scan image' to display the results",
		Example: imageExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("usage: kubescape scan image")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			scanInfo.ImageScan = true

			if len(args) == 0 {
				scanInfo.ScanAll = true
				return getFrameworkCmd(ks, scanInfo).RunE(cmd, []string{"all"})
			}
			return nil
		},
	}
}
