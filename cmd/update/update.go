package update

//This update command updates to the latest kubescape release.
//Example:-
//          kubescape update

import (
	"context"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/spf13/cobra"
)

const (
	installationLink string = "https://kubescape.io/docs/install-cli/"
)

var updateCmdExamples = fmt.Sprintf(`
  # Update to the latest kubescape release
  %[1]s update
`, cautils.ExecName())

func GetUpdateCmd() *cobra.Command {
	updateCmd := &cobra.Command{
		Use:     "update",
		Short:   "Update to latest release version",
		Long:    ``,
		Example: updateCmdExamples,
		RunE: func(_ *cobra.Command, args []string) error {
			ctx := context.TODO()
			v := cautils.NewVersionCheckHandler()
			versionCheckRequest := cautils.NewVersionCheckRequest(cautils.BuildNumber, "", "", "update")
			v.CheckLatestVersion(ctx, versionCheckRequest)

			//Checking the user's version of kubescape to the latest release
			if cautils.BuildNumber == "" || strings.Contains(cautils.BuildNumber, "rc") {
				//your version is unknown
				fmt.Printf("Nothing to update: you are running the development version\n")
			} else if cautils.LatestReleaseVersion == "" {
				//Failed to check for updates
				logger.L().Info(("Failed to check for updates"))
			} else if cautils.BuildNumber == cautils.LatestReleaseVersion {
				//your version == latest version
				logger.L().Info(("Nothing to update: you are running the latest version"), helpers.String("Version", cautils.BuildNumber))
			} else {
				fmt.Printf("Version %s is available. Please refer to our installation documentation: %s\n", cautils.LatestReleaseVersion, installationLink)
			}
			return nil
		},
	}
	return updateCmd
}
