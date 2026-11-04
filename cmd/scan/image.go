package scan

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

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
  # (exceptions require registry references; archive, directory, and SBOM
  # inputs combined with --exceptions fail per image with
  # "Image Exceptions/Unsupported Input")
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

			// Validate the effective command mode, before the core image scanner runs.
			scanInfo.SetScanType(cautils.ScanTypeImage)
			if err := shared.ValidateCommonScanFlags(cmd, scanInfo, shared.ImageScanFormats); err != nil {
				return err
			}
			if len(scanInfo.ExcludeControls) > 0 || commandFlagChanged(cmd, "exclude-controls") {
				return fmt.Errorf("--exclude-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls")
			}
			if scanInfo.SkipControls != "" || commandFlagChanged(cmd, "skip-controls") {
				return fmt.Errorf("--skip-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls")
			}
			if scanInfo.IncludeControls != "" || commandFlagChanged(cmd, "include-controls") {
				return fmt.Errorf("--include-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls")
			}
			if scanInfo.CustomRules != "" || commandFlagChanged(cmd, "custom-rules") {
				return fmt.Errorf("--custom-rules is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls")
			}
			if scanInfo.ControlTimeout != 0 || commandFlagChanged(cmd, "control-timeout") {
				return fmt.Errorf("--control-timeout is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls")
			}
			if scanInfo.ControlsVersion != "" || commandFlagChanged(cmd, "controls-version") {
				return fmt.Errorf("--controls-version is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls")
			}
			if scanInfo.Baseline != "" || commandFlagChanged(cmd, "baseline") {
				return fmt.Errorf("--baseline is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)")
			}
			if scanInfo.BaselineFailOnNew || commandFlagChanged(cmd, "baseline-fail-on-new") {
				return fmt.Errorf("--baseline-fail-on-new is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)")
			}
			if scanInfo.BaselineSeverityThreshold != "" || commandFlagChanged(cmd, "baseline-severity-threshold") {
				return fmt.Errorf("--baseline-severity-threshold is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)")
			}
			if (scanInfo.BaselineGranularity != "" && scanInfo.BaselineGranularity != "evidence") || commandFlagChanged(cmd, "baseline-granularity") {
				return fmt.Errorf("--baseline-granularity is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)")
			}
			if scanInfo.ComplianceThreshold != 0 || commandFlagChanged(cmd, "compliance-threshold") {
				return fmt.Errorf("--compliance-threshold is not supported for image scans: an image scan evaluates vulnerabilities, not posture compliance scores (use --severity-threshold instead)")
			}
			if scanInfo.FailCoverageThreshold != 0 || commandFlagChanged(cmd, "fail-coverage-below") {
				return fmt.Errorf("--fail-coverage-below is not supported for image scans: an image scan evaluates vulnerabilities, not posture control coverage (use --severity-threshold instead)")
			}
			if scanInfo.FailOnDegradedConfig || commandFlagChanged(cmd, "fail-on-degraded-config") {
				return fmt.Errorf("--fail-on-degraded-config is not supported for image scans: an image scan evaluates vulnerabilities, not posture control configurations")
			}
			if scanInfo.ControlsInputs != "" || commandFlagChanged(cmd, "controls-config") {
				return fmt.Errorf("--controls-config is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls")
			}
			if scanInfo.IncludeNamespaces != "" || commandFlagChanged(cmd, "include-namespaces") {
				return fmt.Errorf("--include-namespaces is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes namespaces")
			}
			if scanInfo.ExcludedNamespaces != "" || commandFlagChanged(cmd, "exclude-namespaces") {
				return fmt.Errorf("--exclude-namespaces is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes namespaces")
			}
			if scanInfo.IncludeKinds != "" || commandFlagChanged(cmd, "include-kinds") {
				return fmt.Errorf("--include-kinds is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource kinds")
			}
			if scanInfo.ExcludeKinds != "" || commandFlagChanged(cmd, "exclude-kinds") {
				return fmt.Errorf("--exclude-kinds is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource kinds")
			}
			if scanInfo.LabelSelector != "" || commandFlagChanged(cmd, "label-selector") {
				return fmt.Errorf("--label-selector is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource labels")
			}
			if scanInfo.Incremental || commandFlagChanged(cmd, "incremental") {
				return fmt.Errorf("--incremental is not supported for image scans: an image scan evaluates vulnerabilities, not cached resource manifests")
			}
			if scanInfo.DryRun || commandFlagChanged(cmd, "dry-run") {
				return fmt.Errorf("--dry-run is not supported for image scans: an image scan evaluates vulnerabilities, not cluster resource permissions")
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

			// The invocation is valid from this point on. Runtime and result-gate
			// failures should not print command usage.
			cmd.SilenceUsage = true

			exceedsSeverityThreshold, err := ks.ScanImageContext(ctx, imgScanInfo, scanInfo)
			if !exceedsSeverityThreshold {
				return err
			}

			// Keep the severity breach visible when an exploitability gate or
			// another deferred failure is reported alongside it.
			thresholdErr := fmt.Errorf("result exceeds severity threshold: %s", scanInfo.FailThresholdSeverity)
			if err == nil {
				return thresholdErr
			}
			return errors.Join(err, thresholdErr)
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
