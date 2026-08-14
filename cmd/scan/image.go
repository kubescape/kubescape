package scan

import (
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
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
			defer applyTimeout(scanInfo, ks)()

			if len(args) != 1 {
				return fmt.Errorf("the command takes exactly one image name as an argument")
			}

			if err := shared.ValidateCommonScanFlags(cmd, scanInfo, shared.ImageScanFormats); err != nil {
				return err
			}
			if err := shared.ValidateImageScanInfo(scanInfo); err != nil {
				return err
			}
			credentials := shared.ImageCredentials{
				Authority: scanInfo.RegistryAuthority,
				Username:  scanInfo.RegistryUsername,
				Password:  scanInfo.RegistryPassword,
				Token:     scanInfo.RegistryToken,
			}
			if err := shared.ValidateImageCredentials(credentials); err != nil {
				return err
			}

			imageName := args[0]
			if strings.HasSuffix(imageName, ".tar") && !strings.HasPrefix(imageName, "docker-archive:") && !strings.HasPrefix(imageName, "oci-archive:") {
				if _, err := os.Stat(imageName); err == nil {
					imageName = "docker-archive:" + imageName
				}
			}

			imgScanInfo := &metav1.ImageScanInfo{
				Authority:          credentials.Authority,
				Image:              imageName,
				Username:           credentials.Username,
				Password:           credentials.Password,
				Token:              credentials.Token,
				Exceptions:         scanInfo.UseExceptions,
				UseDefaultMatchers: scanInfo.UseDefaultMatchers,
			}

			exceedsSeverityThreshold, err := ks.ScanImage(imgScanInfo, scanInfo)
			if err != nil {
				return err
			}

			if exceedsSeverityThreshold {
				return fmt.Errorf("result exceeds severity threshold: %s", scanInfo.FailThresholdSeverity)
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&scanInfo.RegistryUsername, "username", "u", "", "Username for registry login")
	cmd.PersistentFlags().StringVarP(&scanInfo.RegistryPassword, "password", "p", "", "Password for registry login")

	return cmd
}
