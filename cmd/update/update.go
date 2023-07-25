package update

//This update command updates to the latest kubescape release.
//Example:-
//          kubescape update

import (
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/spf13/cobra"
)

const (
	installationLink string = "https://github.com/kubescape/kubescape/blob/master/docs/installation.md"
)

var updateCmdExamples = fmt.Sprintf(`
  # Update to the latest kubescape release
  %[1]s update
`, cautils.ExecName())

func GetUpdateCmd() *cobra.Command {
	updateCmd := &cobra.Command{
		Use:     "update",
		Short:   "Update your version",
		Long:    ``,
		Example: updateCmdExamples,
		RunE: func(_ *cobra.Command, args []string) error {
			//Checking the user's version of kubescape to the latest release
			if cautils.BuildNumber == cautils.LatestReleaseVersion {
				//your version == latest version
				logger.L().Info(("You are in the latest version"))
			} else {
				fmt.Printf("please refer to our installation docs in the following link: %s", installationLink)
			}
			return nil
		},
	}
	return updateCmd
}
