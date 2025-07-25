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
			_ = v.CheckLatestVersion(ks.Context(), versioncheck.NewVersionCheckRequest("", versioncheck.BuildNumber, "", "", "version", nil))

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"Your current version is: %s\n",
				versioncheck.BuildNumber,
			)
			return nil
		},
	}
	return versionCmd
}
