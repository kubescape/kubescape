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
  Scan one or more images for vulnerabilities. 

  # Scan the 'nginx' image
  %[1]s scan image "nginx"

  # Scan several images in a single run, sharing one vulnerability database load
  %[1]s scan image "nginx:1.27" "redis:7" "postgres:16"

  # Scan several images with four concurrent workers
  %[1]s scan image "nginx:1.27" "redis:7" --image-scan-concurrency 4

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
		Use:     "image <image>:<tag> [<image>:<tag>...] [flags]",
		Short:   "Scan one or more images for vulnerabilities",
		Example: imageExample,
		Args: func(cmd *cobra.Command, args []string) error {
			return validateImageArgs(args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := deriveTimeoutContext(scanInfo, ks)
			defer cancel()

			if err := validateImageArgs(args); err != nil {
				return err
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
			if err := shared.ValidateImageScanAnonymization(scanInfo); err != nil {
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

			imgScanInfo := &metav1.ImageScanInfo{
				Authority:          credentials.Authority,
				Images:             normalizeImageArgs(args),
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

func validateImageArgs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("the command takes at least one image name as an argument")
	}
	for _, arg := range args {
		if strings.TrimSpace(arg) == "" {
			return fmt.Errorf("image name cannot be empty")
		}
	}
	return nil
}

func normalizeImageArgs(args []string) []string {
	images := make([]string, 0, len(args))
	seen := make(map[string]struct{}, len(args))
	for _, arg := range args {
		image := localArchiveReference(strings.TrimSpace(arg))
		if _, duplicate := seen[image]; duplicate {
			continue
		}
		seen[image] = struct{}{}
		images = append(images, image)
	}
	return images
}

func localArchiveReference(image string) string {
	if !strings.HasSuffix(image, ".tar") || strings.HasPrefix(image, "docker-archive:") || strings.HasPrefix(image, "oci-archive:") {
		return image
	}
	if _, err := os.Stat(image); err != nil {
		return image
	}
	return "docker-archive:" + image
}
