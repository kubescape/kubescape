package scan

import (
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	"github.com/spf13/cobra"
)

// TODO(vladklokun): document image scanning on the Kubescape Docs Hub?
var (
	imageExample = fmt.Sprintf(`
  Scan an image for vulnerabilities. 

  # Scan the 'nginx' image
  %[1]s scan image "nginx"

  # Scan the 'nginx' image and see the full report 
  %[1]s scan image "nginx" -v

  # Scan the 'nginx' image and use exceptions
  %[1]s scan image "nginx" --exceptions exceptions.json

`, cautils.ExecName())
)

// getImageCmd returns the scan image command
func getImageCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	var imgCredentials shared.ImageCredentials
	var exceptions string

	cmd := &cobra.Command{
		Use:     "image <image>:<tag> [flags]",
		Short:   "Scan an image for vulnerabilities",
		Example: imageExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("the command takes exactly one image name as an argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("the command takes exactly one image name as an argument")
			}

			if err := shared.ValidateImageScanInfo(scanInfo); err != nil {
				return err
			}

			imgScanInfo := &metav1.ImageScanInfo{
				Image:      args[0],
				Username:   imgCredentials.Username,
				Password:   imgCredentials.Password,
				Exceptions: exceptions,
			}

			results, err := ks.ScanImage(imgScanInfo, scanInfo)
			if err != nil {
				return err
			}

			if imagescan.ExceedsSeverityThreshold(results, imagescan.ParseSeverity(scanInfo.FailThresholdSeverity)) {
				shared.TerminateOnExceedingSeverity(scanInfo, logger.L())
			}

			return nil
		},
	}

	// The exceptions flag
	cmd.PersistentFlags().StringVarP(&exceptions, "exceptions", "", "", "Path to the exceptions file")
	cmd.PersistentFlags().StringVarP(&imgCredentials.Username, "username", "u", "", "Username for registry login")
	cmd.PersistentFlags().StringVarP(&imgCredentials.Password, "password", "p", "", "Password for registry login")

	return cmd
}
