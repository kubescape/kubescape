package delete

import (
	"github.com/kubescape/kubescape/v2/core/meta"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func GetDeleteCmd(ks meta.IKubescape) *cobra.Command {
	var deleteInfo v1.Delete

	var deleteCmd = &cobra.Command{
		Use:   "delete <command>",
		Short: "Delete configurations in Kubescape SaaS version",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	deleteCmd.PersistentFlags().StringVarP(&deleteInfo.AccountID, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	deleteCmd.PersistentFlags().MarkDeprecated("client-id", "Client ID is no longer supported. Feel free to contact the Kubescape maintainers for more information.")
	deleteCmd.PersistentFlags().MarkDeprecated("secret-key", "Secret Key is no longer supported. Feel free to contact the Kubescape maintainers for more information.")
	deleteCmd.AddCommand(&cobra.Command{
		Use:        "exceptions",
		Deprecated: "Contact Kubescape maintainers for more information.",
	})

	return deleteCmd
}
