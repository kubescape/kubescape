package version

import (
	"context"
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/spf13/cobra"
)

func GetVersionCmd() *cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Get current version",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.TODO()
			v := cautils.NewIVersionCheckHandler(ctx)
			versionCheckRequest := cautils.NewVersionCheckRequest(cautils.BuildNumber, "", "", "version")
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
