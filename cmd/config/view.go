package config

import (
	"os"

	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getViewCmd(ks meta.IKubescape) *cobra.Command {

	// configCmd represents the config command
	return &cobra.Command{
		Use:   "view",
		Short: "View cached configurations",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ks.ViewCachedConfig(&v1.ViewConfig{Writer: os.Stdout})
		},
	}
}
