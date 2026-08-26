package config

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/spf13/cobra"
)

func getDeleteCacheCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cache",
		Short: "Delete the incremental scan cache",
		Long:  "Deletes the cache file used by 'kubescape scan --incremental'. The next --incremental scan will re-evaluate every resource.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := scancache.Delete(getter.DefaultLocalStore); err != nil {
				return err
			}
			logger.L().Info("Incremental scan cache deleted", helpers.String("path", getter.DefaultLocalStore))
			return nil
		},
	}
}
