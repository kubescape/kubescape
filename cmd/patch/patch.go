package patch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	ref "github.com/distribution/distribution/reference"
	"github.com/docker/distribution/reference"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"

	"github.com/spf13/cobra"
)

var patchCmdExamples = fmt.Sprintf(`
  # Patch the nginx:1.22 image
  1) sudo buildkitd        # start buildkitd service, run in seperate terminal
  2) sudo %[1]s patch --image docker.io/library/nginx:1.22   # patch the image

  # The patch command can also be run without sudo privileges
  # Documentation: https://github.com/kubescape/kubescape/tree/master/cmd/patch
`, cautils.ExecName())

func GetPatchCmd(ks meta.IKubescape) *cobra.Command {
	var patchInfo metav1.PatchInfo
	var scanInfo cautils.ScanInfo

	patchCmd := &cobra.Command{
		Use:     "patch --image <image>:<tag> [flags]",
		Short:   "Patch container images with vulnerabilities",
		Long:    `Patch command is for automatically patching images with vulnerabilities.`,
		Example: patchCmdExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("the command takes no arguments")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := shared.ValidateImageScanInfo(&scanInfo); err != nil {
				return err
			}

			if err := validateImagePatchInfo(&patchInfo); err != nil {
				return err
			}

			results, err := ks.Patch(context.Background(), &patchInfo, &scanInfo)
			if err != nil {
				return err
			}

			if imagescan.ExceedsSeverityThreshold(results, imagescan.ParseSeverity(scanInfo.FailThresholdSeverity)) {
				shared.TerminateOnExceedingSeverity(&scanInfo, logger.L())
			}

			return nil
		},
	}

	patchCmd.PersistentFlags().StringVarP(&patchInfo.Image, "image", "i", "", "Application image name and tag to patch")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.PatchedImageTag, "tag", "t", "", "Tag for the patched image. Defaults to '<image-tag>-patched' ")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.BuildkitAddress, "address", "a", "unix:///run/buildkit/buildkitd.sock", "Address of buildkitd service, defaults to local buildkitd.sock")
	patchCmd.PersistentFlags().DurationVar(&patchInfo.Timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")

	patchCmd.PersistentFlags().StringVarP(&patchInfo.Username, "username", "u", "", "Username for registry login")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.Password, "password", "p", "", "Password for registry login")

	patchCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "", `Output file format. Supported formats: "pretty-printer", "json", "sarif"`)
	patchCmd.PersistentFlags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. Print output to file and not stdout")
	patchCmd.PersistentFlags().BoolVarP(&scanInfo.VerboseMode, "verbose", "v", false, "Display full report. Default to false")

	patchCmd.PersistentFlags().StringVarP(&scanInfo.FailThresholdSeverity, "severity-threshold", "s", "", "Severity threshold is the severity of a vulnerability at which the command fails and returns exit code 1")

	return patchCmd
}

// validateImagePatchInfo validates the image patch info for the `patch` command
func validateImagePatchInfo(patchInfo *metav1.PatchInfo) error {

	if patchInfo.Image == "" {
		return errors.New("image tag is required")
	}

	// Convert image to canonical format (required by copacetic for patching images)
	patchInfoImage, err := cautils.NormalizeImageName(patchInfo.Image)
	if err != nil {
		return nil
	}

	// Parse the image full name to get image name and tag
	named, err := ref.ParseNamed(patchInfoImage)
	if err != nil {
		return err
	}

	// If no tag or digest is provided, default to 'latest'
	if ref.IsNameOnly(named) {
		logger.L().Warning("Image name has no tag or digest, using latest as tag")
		named = ref.TagNameOnly(named)
	}
	patchInfo.Image = named.String()

	// If no patched image tag is provided, default to '<image-tag>-patched'
	if patchInfo.PatchedImageTag == "" {

		taggedName, ok := named.(ref.Tagged)
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
