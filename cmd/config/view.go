package config

import (
	"os"

	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/meta"
	v1 "github.com/armosec/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getViewCmd(ks meta.IKubescape) *cobra.Command {

	// configCmd represents the config command
	return &cobra.Command{
		Use:   "view",
		Short: "View cached configurations",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			if err := ks.ViewCachedConfig(&v1.ViewConfig{Writer: os.Stdout}); err != nil {
				logger.L().Fatal(err.Error())
			}
		},
	}
}
