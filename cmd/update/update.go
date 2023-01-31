package update

//This update command updates to the latest kubescape release.
//Example:-
//          kubescape update

import (
	"fmt"
	"os/exec"
	"runtime"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/spf13/cobra"
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

				const OSTYPE string = runtime.GOOS
				var ShellToUse string
				switch OSTYPE {

				case "windows":
					cautils.StartSpinner()
					//run the installation command for windows
					ShellToUse = "powershell"
					_, err := exec.Command(ShellToUse, "-c", "iwr -useb https://raw.githubusercontent.com/kubescape/kubescape/master/install.ps1 | iex").Output()

					if err != nil {
						logger.L().Fatal(err.Error())
					}
					cautils.StopSpinner()

				default:
					ShellToUse = "bash"
					cautils.StartSpinner()
					//run the installation command for linux and macOS
					_, err := exec.Command(ShellToUse, "-c", "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash").Output()
					if err != nil {
						logger.L().Fatal(err.Error())
					}

					cautils.StopSpinner()
				}
			}
			return nil
		},
	}
	return updateCmd
}
