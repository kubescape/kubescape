package version

import (
	"context"
	"fmt"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/spf13/cobra"
)

func GetVersionCmd() *cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Get current version",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.TODO()
			v := versioncheck.NewIVersionCheckHandler(ctx)
			versionCheckRequest := versioncheck.NewVersionCheckRequest("", versioncheck.BuildNumber, "", "", "version", nil)
			v.CheckLatestVersion(ctx, versionCheckRequest)
			fmt.Fprintf(cmd.OutOrStdout(),
				"Your current version is: %s\n",
				versionCheckRequest.ClientVersion,
			)
			return nil
		},
	}
	return versionCmd
}
