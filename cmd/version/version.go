package version

import (
	"fmt"
	"github.com/kubescape/kubescape/v3/core/meta"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/spf13/cobra"
)

func GetVersionCmd(ks meta.IKubescape) *cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Get current version",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			v := versioncheck.NewIVersionCheckHandler(ks.Context())
			versionCheckRequest := versioncheck.NewVersionCheckRequest("", versioncheck.BuildNumber, "", "", "version", nil)
			v.CheckLatestVersion(ks.Context(), versionCheckRequest)
			fmt.Fprintf(cmd.OutOrStdout(),
				"Your current version is: %s\n",
				versionCheckRequest.ClientVersion,
			)
			return nil
		},
	}
	return versionCmd
}
