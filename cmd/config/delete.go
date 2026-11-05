package config

import (
	"errors"

	"github.com/kubescape/kubescape/v4/core/meta"
	v1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getDeleteCmd(ks meta.IKubescape) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [KEY...]",
		Short: "Delete cached configurations",
		Long:  ``,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if ks == nil {
				return errors.New("uninitialized kubescape interface")
			}
			return ks.DeleteCachedConfig(&v1.DeleteConfig{
				Keys: args,
			})
		},
	}
	cmd.AddCommand(getDeleteCacheCmd())
	return cmd
}
