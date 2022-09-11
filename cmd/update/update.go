package update

//This update command updates to the latest kubescape release.
//Example:-
//          kubescape update

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/spf13/cobra"
)

func GetUpdateCmd() *cobra.Command {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update your version",
		Long:  ``,
		RunE: func(_ *cobra.Command, args []string) error {
			vu := cautils.NewIVersionCheckHandlerU()
			vu.CheckLatestVersionU(cautils.NewVersionCheckRequestU(cautils.BuildNumber, "", "", "version"))
			//Checking the user's version of kubescape to the latest release
			if cautils.BuildNumber == cautils.LatestReleaseVersion {
				//your version == latest version
				fmt.Println("You are in the latest version")
			} else {
				//execute the install.sh if linux, install.ps1 for windows,.....depending on your OS
				var OSTYPE string = runtime.GOOS
				if OSTYPE == "linux" {

					//run the installation command for linux
					cmd, err := exec.Command("./install.sh").Output()
					if err != nil {
						log.Fatal(err)
					}
					fmt.Println(string(cmd))
				} else if OSTYPE == "windows" {
					//run the installation command for windows
					cmd, err := exec.Command("./install.ps1").Output()
					if err != nil {
						log.Fatal(err)
					}
					fmt.Println(string(cmd))
				} else {
					//run the installation command for macOS
					cmd, err := exec.Command("./macinstall/kubescape.rb").Output()
					if err != nil {
						log.Fatal(err)
					}
					fmt.Println(string(cmd))
				}
			}
			return nil
		},
	}
	return updateCmd
}
