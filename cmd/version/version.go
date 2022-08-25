package version

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/spf13/cobra"
)

func GetVersionCmd() *cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Get current version",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			v := cautils.NewIVersionCheckHandler()
			v.CheckLatestVersion(cautils.NewVersionCheckRequest(cautils.BuildNumber, "", "", "version"))
			fmt.Fprintln(os.Stdout, "Your current version is: "+cautils.BuildNumber)
			return nil
		},
	}
	return versionCmd
}
