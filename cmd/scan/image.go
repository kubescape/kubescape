package scan

import (
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
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

  # Scan the linux/amd64 variant from a multi-architecture image index
  %[1]s scan image "nginx" --platform linux/amd64

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
			ctx, cancel := deriveTimeoutContext(scanInfo, ks)
			defer cancel()

			if len(args) != 1 {
				return fmt.Errorf("the command takes exactly one image name as an argument")
			}

			if err := shared.ValidateCommonScanFlags(cmd, scanInfo, shared.ImageScanFormats); err != nil {
				return err
			}
			if len(scanInfo.ExcludeControls) > 0 {
				return fmt.Errorf("--exclude-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls")
			}
			if len(scanInfo.NotifyURLs) > 0 {
				return fmt.Errorf("--notify is not supported for image-only scans yet")
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
				Platform:           scanInfo.ImagePlatform,
				Username:           credentials.Username,
				Password:           credentials.Password,
				Token:              credentials.Token,
				Exceptions:         scanInfo.UseExceptions,
				UseDefaultMatchers: scanInfo.UseDefaultMatchers,
			}

			exceedsSeverityThreshold, err := ks.ScanImageContext(ctx, imgScanInfo, scanInfo)
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
	cmd.PersistentFlags().StringVar(&scanInfo.ImagePlatform, "platform", "", "OCI platform to scan, for example linux/amd64 or linux/arm64/v8")

	return cmd
}
