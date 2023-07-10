package scan

import (
	"fmt"
	"strings"
	"context"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/kubescape/kubescape/v2/pkg/imagescan"

	"github.com/spf13/cobra"
	"github.com/anchore/grype/grype/presenter"
)

// TODO(vladklokun): image scan documentation
var (
	imageExample = fmt.Sprintf(`
  # Scan the 'nginx' image
  %[1]s scan image "nginx"

  # Scan list of images separated with a comma
  %[1]s scan image nginx,redis

  # Image scan documentation:
  # https://hub.armosec.io/docs/images
`, cautils.ExecName())
)

// imageCmd represents the image command
func getImageCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	return &cobra.Command{
		Use:     "image <image name>[,<image name>]",
		Short:   "Scans images for vulnerabilities",
		Example: imageExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				images := strings.Split(args[0], ",")
				if len(images) > 1 {
					for _, image := range images {
						if image == "" {
							return fmt.Errorf("usage: <image-0>,<image-1>")
						}
					}
				}
			} else {
				return fmt.Errorf("requires at least one image name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			userInput := args[0]
			dbCfg, _ := imagescan.NewDefaultDBConfig()
			svc := imagescan.NewScanService(dbCfg)

			scanResults, err := svc.Scan(ctx, userInput)

			presenterConfig, _ := presenter.ValidatedConfig("table", "", false)
			pres := presenter.GetPresenter(presenterConfig, *scanResults)

			pres.Present(os.Stdout)

			return err
		},
	}
}

// validateImageScanInfo validates the ScanInfo struct for the `image` command
func validateImageScanInfo(scanInfo *cautils.ScanInfo) error {
	severity := scanInfo.FailThresholdSeverity

	if scanInfo.Submit && scanInfo.OmitRawResources {
		return fmt.Errorf("you can use `omit-raw-resources` or `submit`, but not both")
	}

	if err := validateSeverity(severity); severity != "" && err != nil {
		return err
	}
	return nil
}
