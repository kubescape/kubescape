package patch

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var patchCmdExamples = fmt.Sprintf(`
  # Patch the nginx:1.22 image
  1) sudo buildkitd        # start buildkitd service, run in separate terminal
  2) sudo %[1]s patch --image docker.io/library/nginx:1.22   # patch the image

  # The patch command can also be run without sudo privileges
  # Documentation: https://github.com/kubescape/kubescape/tree/master/cmd/patch
`, cautils.ExecName())

func GetPatchCmd(ks meta.IKubescape) *cobra.Command {
	var patchInfo metav1.PatchInfo
	var scanInfo cautils.ScanInfo
	var useDefaultMatchers bool

	patchCmd := &cobra.Command{
		Use:     "patch --image <image>:<tag> [flags]",
		Short:   "Patch container images to fix known OS-level vulnerabilities",
		Long:    `Automatically patch container images to remediate known OS-level vulnerabilities using Copa and BuildKit.`,
		Example: patchCmdExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("the command takes no arguments")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if f := cmd.Flags().Lookup("format"); f != nil && f.Changed && scanInfo.Format == "" {
				return fmt.Errorf("format cannot be empty, supported formats: pretty-printer, json, sarif")
			}
			if f := cmd.Flags().Lookup("format"); f != nil && f.Changed && scanInfo.Format != "" {
				supported := []string{"pretty-printer", "json", "sarif"}
				valid := slices.Contains(supported, scanInfo.Format)
				if !valid {
					return fmt.Errorf("invalid format %q, supported formats: pretty-printer, json, sarif", scanInfo.Format)
				}
			}
			if err := shared.ValidateImageScanInfo(&scanInfo); err != nil {
				return err
			}

			if err := validateImagePatchInfo(&patchInfo); err != nil {
				return err
			}

			// Set the UseDefaultMatchers field in scanInfo
			scanInfo.UseDefaultMatchers = useDefaultMatchers

			exceedsSeverityThreshold, err := ks.Patch(&patchInfo, &scanInfo)
			if err != nil {
				return err
			}

			if exceedsSeverityThreshold {
				shared.TerminateOnExceedingSeverity(&scanInfo, logger.L())
			}

			return nil
		},
	}

	patchCmd.PersistentFlags().StringVarP(&patchInfo.Image, "image", "i", "", "Application image name and tag to patch")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.PatchedImageTag, "tag", "t", "", "Tag for the patched image. Defaults to '<image-tag>-patched' ")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.BuildkitAddress, "address", "a", "unix:///run/buildkit/buildkitd.sock", "Address of buildkitd service, defaults to local buildkitd.sock")
	patchCmd.PersistentFlags().DurationVar(&patchInfo.Timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")
	patchCmd.PersistentFlags().BoolVar(&patchInfo.IgnoreError, "ignore-errors", false, "Ignore errors and continue patching other images. Default to false")
	patchCmd.PersistentFlags().BoolVar(&patchInfo.Push, "push", false, "Push the patched image to the source registry. Default to false (the patched image is only loaded into the local image store). If set, this overrides output-mode to 'image'.")
	patchCmd.PersistentFlags().StringVar(&patchInfo.OutputMode, "output-mode", "docker", "Output mode for the patched image (docker, image, oci, local)")
	patchCmd.PersistentFlags().StringVar(&patchInfo.OutputPath, "output-path", "", "Destination path for oci or local output mode")

	patchCmd.PersistentFlags().StringVarP(&patchInfo.Username, "username", "u", "", "Username for registry login")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.Password, "password", "p", "", "Password for registry login")

	patchCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "", `Output file format. Supported formats: "pretty-printer", "json", "sarif"`)
	patchCmd.PersistentFlags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. Print output to file and not stdout")
	patchCmd.PersistentFlags().BoolVarP(&scanInfo.VerboseMode, "verbose", "v", false, "Display full report. Default to false")

	patchCmd.PersistentFlags().StringVarP(&scanInfo.FailThresholdSeverity, "severity-threshold", "s", "", "Severity threshold is the severity of a vulnerability at which the command fails and returns exit code 1")
	patchCmd.PersistentFlags().BoolVarP(&useDefaultMatchers, "use-default-matchers", "", true, "Use default matchers (true) or CPE matchers (false) for image scanning")
	patchCmd.PersistentFlags().StringVar(&scanInfo.ListingURL, "grype-db-url", "", "Grype vulnerability database URL")

	return patchCmd
}

// validateImagePatchInfo validates the image patch info for the `patch` command
func validateImagePatchInfo(patchInfo *metav1.PatchInfo) error {

	if patchInfo.Image == "" {
		return errors.New("image tag is required")
	}

	if patchInfo.Push {
		if patchInfo.OutputMode != "" && patchInfo.OutputMode != "docker" && patchInfo.OutputMode != "image" {
			return fmt.Errorf("--push and --output-mode %q are mutually exclusive; --push always pushes to the registry (output-mode=image)", patchInfo.OutputMode)
		}
		patchInfo.OutputMode = "image"
	}

	supportedModes := []string{"docker", "image", "oci", "local"}
	if !slices.Contains(supportedModes, patchInfo.OutputMode) {
		return fmt.Errorf("invalid output mode %q, supported modes: docker, image, oci, local", patchInfo.OutputMode)
	}

	if (patchInfo.OutputMode == "oci" || patchInfo.OutputMode == "local") && patchInfo.OutputPath == "" {
		return fmt.Errorf("output-path is required when output-mode is %s", patchInfo.OutputMode)
	}

	// Convert image to canonical format (required by copacetic for patching images)
	patchInfoImage, err := cautils.NormalizeImageName(patchInfo.Image)
	if err != nil {
		return err
	}

	// Parse the image full name to get image name and tag
	named, err := reference.ParseNamed(patchInfoImage)
	if err != nil {
		return err
	}

	// If no tag or digest is provided, default to 'latest'
	if reference.IsNameOnly(named) {
		logger.L().Warning("Image name has no tag or digest, using latest as tag")
		named = reference.TagNameOnly(named)
	}
	patchInfo.Image = named.String()

	// If no patched image tag is provided, default to '<image-tag>-patched'
	if patchInfo.PatchedImageTag == "" {

		taggedName, ok := named.(reference.Tagged)
		if !ok {
			return errors.New("unexpected error while parsing image tag")
		}

		patchInfo.ImageTag = taggedName.Tag()

		if patchInfo.ImageTag == "" {
			logger.L().Warning("No tag provided, defaulting to 'patched'")
			patchInfo.PatchedImageTag = "patched"
		} else {
			patchInfo.PatchedImageTag = fmt.Sprintf("%s-%s", patchInfo.ImageTag, "patched")
		}

	}

	// Extract the "image" name from the canonical Image URL
	// If it's an official docker image, we store just the "image-name". Else if a docker repo then we store as "repo/image". Else complete URL
	ref, _ := reference.ParseNormalizedNamed(patchInfo.Image)
	imageName := named.Name()
	if strings.Contains(imageName, "docker.io/library/") {
		imageName = reference.Path(ref)
		imageName = imageName[strings.LastIndex(imageName, "/")+1:]
	} else if strings.Contains(imageName, "docker.io/") {
		imageName = reference.Path(ref)
	}
	patchInfo.ImageName = imageName

	return nil
}
