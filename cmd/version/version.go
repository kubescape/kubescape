package version

import (
	"context"
	"fmt"
	"os"

	"github.com/kubescape/go-logger"
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
			v.CheckLatestVersion(ctx, cautils.NewVersionCheckRequest(cautils.BuildNumber, "", "", "version"))
			fmt.Fprintf(os.Stdout,
				"Your current version is: %s\n",
				cautils.BuildNumber,
			)
			logger.L().Debug(fmt.Sprintf("git enabled in build: %t", isGitEnabled()))
			return nil
		},
	}
	return versionCmd
}
