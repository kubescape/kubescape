package patch

import (
	"context"
	"errors"
	"fmt"
	"time"

	ref "github.com/distribution/distribution/reference"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"

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

	patchCmd := &cobra.Command{
		Use:     "patch --image <image-tag> [flags]",
		Short:   "Patch container images with vulnerabilities ",
		Long:    `Patch command is for automatically patching images with vulnerabilities.`,
		Example: patchCmdExamples,
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := validateImagePatchInfo(&patchInfo); err != nil {
				return err
			}

			return ks.Patch(context.Background(), &patchInfo)
		},
	}

	patchCmd.PersistentFlags().StringVarP(&patchInfo.Image, "image", "i", "", "Application image name and tag to patch")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.PatchedImageTag, "tag", "t", "", "Tag for the patched image. Defaults to '<image-tag>-patched' ")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.BuildkitAddress, "address", "a", "unix:///run/buildkit/buildkitd.sock", "Address of buildkitd service, defaults to local buildkitd.sock")
	patchCmd.PersistentFlags().DurationVar(&patchInfo.Timeout, "timeout", 5*time.Minute, "Timeout for the operation, defaults to '5m'")
	patchCmd.PersistentFlags().BoolVarP(&patchInfo.IncludeReport, "report", "r", false, "Generate & save a before and after report for the image (json format))")

	patchCmd.PersistentFlags().StringVarP(&patchInfo.Username, "username", "u", "", "Username for registry login")
	patchCmd.PersistentFlags().StringVarP(&patchInfo.Password, "password", "p", "", "Password for registry login")

	return patchCmd
}

// validateImagePatchInfo validates the image patch info for the `patch` command
func validateImagePatchInfo(patchInfo *metav1.PatchInfo) error {

	if patchInfo.Image == "" {
		return errors.New("image tag is required")
	}

	// Check if image is in canonical format (required by copacetic for patching images)
	// Parse the image full name to get image name and tag
	named, err := ref.ParseNamed(patchInfo.Image)
	if err != nil{
		return err
	}

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
	
	patchInfo.ImageName = named.Name()

	return nil
}
