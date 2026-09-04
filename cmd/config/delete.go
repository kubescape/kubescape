package config

import (
	"github.com/kubescape/kubescape/v4/core/meta"
	v1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getDeleteCmd(ks meta.IKubescape) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete cached configurations",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ks.DeleteCachedConfig(&v1.DeleteConfig{
				Keys: args,
			})
		},
	}
	cmd.AddCommand(getDeleteCacheCmd())
	return cmd
}
