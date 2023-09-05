package image

import (
	"context"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/cmd/utils"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v2/pkg/imagescan"
	"github.com/spf13/cobra"
)

// TODO(vladklokun): document image scanning on the Kubescape Docs Hub?
var (
	imageExample = fmt.Sprintf(`
  Scan an image for vulnerabilities. 

  # Scan the 'nginx' image
  %[1]s scan image "nginx"
`, cautils.ExecName())
)

// imageCmd represents the image command
func getScanCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo, imgCredentials *imageCredentials) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scan <image>:<tag> [flags]",
		Short:   "Scan container images for vulnerabilities",
		Example: imageExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("the command takes exactly one image name as an argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateImageScanInfo(scanInfo); err != nil {
				return err
			}

			imgScanInfo := &metav1.ImageScanInfo{
				Image:    args[0],
				Username: imgCredentials.Username,
				Password: imgCredentials.Password,
			}

			results, err := ks.ScanImage(context.Background(), imgScanInfo, scanInfo)
			if err != nil {
				return err
			}

			if imagescan.ExceedsSeverityThreshold(results, imagescan.ParseSeverity(scanInfo.FailThresholdSeverity)) {
				utils.TerminateOnExceedingSeverity(scanInfo, logger.L())
			}

			return nil
		},
	}

	return cmd
}

// validateImageScanInfo validates the ScanInfo struct for the `image` command
func validateImageScanInfo(scanInfo *cautils.ScanInfo) error {
	severity := scanInfo.FailThresholdSeverity

	if err := utils.ValidateSeverity(severity); severity != "" && err != nil {
		return err
	}
	return nil
}
